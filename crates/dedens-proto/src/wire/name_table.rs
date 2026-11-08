//! The name table of [`Writer`](super::Writer): the offsets of the names written, keyed on a hash of their
//! suffixes, to point to them (RFC 1035 §4.1.4, D10, D112). Its tests drive it through the `Writer` too.

use std::hash::{BuildHasher, RandomState};
use std::sync::OnceLock;

/// Slots of the name table: a power of two, a multiple of [`GROUP`].
const TABLE_SLOTS: usize = 256;

/// Slots a probe reads at once: their 8 tags fit a word.
const GROUP: usize = 8;

/// Groups of the name table.
const GROUPS: usize = TABLE_SLOTS / GROUP;

/// Names of one tag that a lookup compares with the message before it gives up: names chosen to share a tag lose
/// their own compression, not the encoder's time (D112).
const MAX_COMPARES: usize = 4;

/// How many suffixes a [`Writer`](super::Writer) remembers, 3/4 of the slots so probes stay short; a message with more
/// distinct names compresses the later ones less.
const TABLE_CAPACITY: usize = TABLE_SLOTS / 4 * 3;

/// A suffix of a name, as [`suffix_hashes`] lists it: where it starts in the wire-form name, at most 253, and
/// the top 32 bits of its hash but for the 8 that hold the start.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Suffix(u32);

impl Suffix {
    const START: u32 = 0xFF;

    /// The suffix of the name that starts at `start`, of `hash`.
    fn new(start: usize, hash: u64) -> Self {
        let hash = u32::try_from(hash >> 32).unwrap_or_default();
        Self(hash & !Self::START | u32::try_from(start).unwrap_or_default() & Self::START)
    }

    /// Where the suffix starts in the wire-form name.
    pub(super) fn start(self) -> usize {
        usize::try_from(self.0 & Self::START).unwrap_or_default()
    }

    /// The bits of the hash the name table uses: the same for every name with this suffix.
    pub(super) const fn hash(self) -> u32 {
        self.0
    }
}

/// Fills `hashes` with a [`Suffix`] for each suffix of the wire-form name `wire` that starts at a label, longest
/// first, and returns them; `None` when the name has more labels than `hashes` holds. Folded from the root,
/// each byte of the name is hashed once, however many suffixes there are. The hash starts from `seed` and
/// keeps case: names are matched byte for byte (D10).
pub(super) fn suffix_hashes<'h, const N: usize>(
    wire: &[u8],
    seed: u64,
    hashes: &'h mut [Suffix; N],
) -> Option<&'h [Suffix]> {
    // Each entry holds where its label starts, until the hash is put above it.
    let mut count = 0;
    let mut at = 0;
    while let Some(&len) = wire.get(at).filter(|&&len| len != 0) {
        *hashes.get_mut(count)? = Suffix::new(at, 0);
        count += 1;
        at += 1 + usize::from(len);
    }
    let mut hash = seed;
    for suffix in hashes.iter_mut().take(count).rev() {
        let start = suffix.start();
        let len = usize::from(wire.get(start).copied().unwrap_or_default());
        hash = fold(hash, wire, start, start + 1 + len);
        *suffix = Suffix::new(start, hash);
    }
    hashes.get(..count)
}

/// One step of the hash: the product of `hash` and `word`, as wide as the registers twice over, folded in two.
/// Every input bit reaches every output bit, which `FxHash`'s multiplication by a constant does not do: bits
/// of two words can be flipped so that they cancel, whatever `hash` held.
fn mix(hash: u64, word: u64) -> u64 {
    let product = u128::from(hash ^ word) * 0x9E37_79B9_7F4A_7C15;
    // Both halves of the product, so the high bits do not have to carry the whole result.
    let folded = product >> 64 ^ product & u128::from(u64::MAX);
    u64::try_from(folded).unwrap_or_default()
}

/// Mixes the label at `wire[start..end]`, its length byte first, into `hash`, a word at a time. Reads the
/// bytes before `start` for a label of up to 8 bytes, but not into the hash.
fn fold(mut hash: u64, wire: &[u8], start: usize, end: usize) -> u64 {
    let word = |at: usize| {
        let bytes = wire.get(at..at + 8).unwrap_or_default();
        u64::from_le_bytes(<[u8; 8]>::try_from(bytes).unwrap_or_default())
    };
    let len = end - start;
    if len > 8 {
        let mut at = start;
        while at + 8 < end {
            hash = mix(hash, word(at));
            at += 8;
        }
        // The last word overlaps the one before it, so no byte of the label is left out.
        mix(hash, word(end - 8))
    } else if end >= 8 {
        // The label is the last bytes of the word before `end`: shifted down, they start it.
        mix(hash, word(end - 8) >> (8 * (8 - len)))
    } else {
        // Zeros past the end cannot make two labels equal: the length byte differs.
        let tail = wire.get(start..end).unwrap_or_default();
        mix(
            hash,
            tail.iter().rev().fold(0, |w, &b| w << 8 | u64::from(b)),
        )
    }
}

/// Offsets of the names written so far, to point to them (RFC 1035 §4.1.4).
///
/// An open-addressing hash table of offsets keyed on [`suffix_hashes`]: fixed capacity, so no allocation (D10),
/// and 768 bytes to clear per message. Beside its offset a slot has an 8-bit tag of its hash, 0 for an empty
/// slot; a probe reads the tags of a group of slots in one word and compares a name with the written message
/// only where the tag agrees, and gives up after a few (D112). Names are matched byte for byte against the
/// written message, so each keeps its own case (RFC 4343 §4).
#[derive(Debug)]
pub(super) struct NameTable {
    /// Offset of the name in each slot; meaningless while the slot is empty.
    offsets: [u16; TABLE_SLOTS],
    /// The tags of the slots, a group in each word, the first slot in the low byte; a tag is 1 to 255, 0 is an
    /// empty slot.
    tags: [u64; GROUPS],
    len: usize,
    /// Where [`suffix_hashes`] starts: random for each process, so that names cannot be chosen to share a group.
    pub(super) seed: u64,
}

impl NameTable {
    pub(super) fn new() -> Self {
        static SEED: OnceLock<u64> = OnceLock::new();
        Self::with_seed(*SEED.get_or_init(|| RandomState::new().hash_one(0_u8)))
    }

    const fn with_seed(seed: u64) -> Self {
        Self {
            offsets: [0; TABLE_SLOTS],
            tags: [0; GROUPS],
            len: 0,
            seed,
        }
    }

    /// The groups to look in for a name of `hash`, from its home, its top 5 bits, on.
    fn probe(hash: u32) -> impl Iterator<Item = usize> {
        let home = usize::try_from(hash >> 27).unwrap_or_default();
        (0..GROUPS).map(move |step| (home + step) % GROUPS)
    }

    /// The tag of a name of `hash`: 8 bits under its home's, never 0.
    fn tag(hash: u32) -> u8 {
        u8::try_from(hash >> 19 & 0xFF).unwrap_or_default().max(1)
    }

    /// The tags of the slots of `group`.
    fn group(&self, group: usize) -> u64 {
        self.tags.get(group).copied().unwrap_or_default()
    }

    /// Remembers that the name of `hash` starts at `offset`, which a pointer can reach; `false` when the table
    /// is full.
    pub(super) fn add(&mut self, offset: u16, hash: u32) -> bool {
        if self.len >= TABLE_CAPACITY {
            return false;
        }
        for group in Self::probe(hash) {
            let empties = zero_bytes(self.group(group));
            if empties == 0 {
                continue;
            }
            let first = empties.trailing_zeros() / 8;
            let slot = group * GROUP + usize::try_from(first).unwrap_or_default();
            if let (Some(tags), Some(stored)) =
                (self.tags.get_mut(group), self.offsets.get_mut(slot))
            {
                *tags |= u64::from(Self::tag(hash)) << (8 * first);
                *stored = offset;
                self.len += 1;
                return true;
            }
        }
        false
    }

    /// Forgets the names starting at or after `len`.
    ///
    /// They are the last ones added, so no name left behind was probed past their slots: emptying them keeps
    /// every probe sequence whole.
    pub(super) fn truncate(&mut self, len: usize) {
        for (group, tags) in self.tags.iter_mut().enumerate() {
            for slot in 0..GROUP {
                let shift = 8 * slot;
                let at = group * GROUP + slot;
                let offset = self.offsets.get(at).copied().unwrap_or_default();
                if *tags >> shift & 0xFF != 0 && usize::from(offset) >= len {
                    *tags &= !(0xFF << shift);
                    self.len -= 1;
                }
            }
        }
    }

    /// The offset of an earlier name equal to `suffix` (wire form, root included, of `hash`), if any.
    pub(super) fn find(&self, written: &[u8], suffix: &[u8], hash: u32) -> Option<u16> {
        let tag = u64::from(Self::tag(hash)) * 0x0101_0101_0101_0101;
        let mut compares = 0;
        for group in Self::probe(hash) {
            let tags = self.group(group);
            let mut hits = zero_bytes(tags ^ tag);
            while hits != 0 {
                if compares == MAX_COMPARES {
                    return None;
                }
                compares += 1;
                let first = usize::try_from(hits.trailing_zeros() / 8).unwrap_or_default();
                let offset = *self.offsets.get(group * GROUP + first)?;
                if name_matches(written, usize::from(offset), suffix) {
                    return Some(offset);
                }
                hits &= hits - 1;
            }
            // A group with room left ends the probe: a name that overflowed it would have filled it.
            if zero_bytes(tags) != 0 {
                return None;
            }
        }
        None
    }
}

/// `0x80` in each byte of `word` that is 0, `0` in the others, with no false positives.
const fn zero_bytes(word: u64) -> u64 {
    const LOW: u64 = 0x7F7F_7F7F_7F7F_7F7F;
    !((word & LOW).wrapping_add(LOW) | word | LOW)
}

/// Whether the name at `offset` in `written`, following its pointers, is the wire-form name `suffix`.
///
/// Pointers in `written` were made by [`Writer::put_name_compressed`](super::Writer::put_name_compressed) and
/// point backwards; one that does not ends the match, so this always ends.
fn name_matches(written: &[u8], mut offset: usize, mut suffix: &[u8]) -> bool {
    loop {
        let Some(&len) = written.get(offset) else {
            return false;
        };
        match len {
            0 => return suffix == [0],
            l if l & 0xC0 == 0xC0 => {
                let Some(&low) = written.get(offset + 1) else {
                    return false;
                };
                let target = usize::from(l & 0x3F) << 8 | usize::from(low);
                if target >= offset {
                    return false;
                }
                offset = target;
            }
            l => {
                let end = offset + 1 + usize::from(l);
                let Some(label) = written.get(offset..end) else {
                    return false;
                };
                let Some(rest) = suffix.strip_prefix(label) else {
                    return false;
                };
                suffix = rest;
                offset = end;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::HEADER_LEN;
    use crate::name::{MAX_NAME_LEN, Name};
    use crate::wire::{LONGEST_FIRST, MAX_LABELS, POINTER_LIMIT, Writer};
    /// The name of `labels`.
    fn name_of(labels: &[&[u8]]) -> Name<'static> {
        Name::from_labels(labels.iter().copied()).unwrap()
    }

    /// The wire form of `name`.
    fn wire_of(name: &Name<'_>) -> Vec<u8> {
        name.to_wire(&mut [0; MAX_NAME_LEN]).to_vec()
    }

    /// The hash the table keys the whole of `name` on.
    fn hash_of(name: &Name<'_>, seed: u64) -> u32 {
        let mut hashes = [Suffix::default(); MAX_LABELS];
        suffix_hashes(&wire_of(name), seed, &mut hashes).unwrap()[0].hash()
    }

    /// Writes `names` after a header, compressed, and returns what was written past it.
    fn compressed(names: &[Name<'_>]) -> Vec<u8> {
        let mut buf = [0; 2048];
        let mut w = Writer::new(&mut buf);
        w.put_bytes(&[0; HEADER_LEN]).unwrap();
        for name in names {
            w.put_name_compressed(name).unwrap();
        }
        w.written().get(HEADER_LEN..).unwrap().to_vec()
    }

    /// Names whose hashes agree on the group and the tag share a probe sequence and are told apart by the
    /// comparison with the message, not by the tag; a lookup compares at most [`MAX_COMPARES`] of them, so the
    /// next one is not found, and one that was never added is not found either.
    #[test]
    fn names_of_one_tag_are_compared_in_full_up_to_a_cap() {
        const SEED: u64 = 1;
        let mut buckets = std::collections::HashMap::<u32, Vec<Name<'static>>>::new();
        let same = (0..)
            .find_map(|i| {
                let name = name_of(&[format!("n{i}").as_bytes()]);
                let bucket = buckets.entry(hash_of(&name, SEED) >> 19).or_default();
                bucket.push(name);
                (bucket.len() == MAX_COMPARES + 2).then(|| bucket.clone())
            })
            .unwrap();
        let mut written = vec![0; HEADER_LEN];
        let mut table = NameTable::with_seed(SEED);
        let mut offsets = Vec::new();
        for name in &same[..=MAX_COMPARES] {
            let offset = u16::try_from(written.len()).unwrap();
            assert!(table.add(offset, hash_of(name, SEED)));
            offsets.push(offset);
            written.extend(wire_of(name));
        }
        let find = |name: &Name<'_>| table.find(&written, &wire_of(name), hash_of(name, SEED));
        for (name, &offset) in same.iter().zip(&offsets).take(MAX_COMPARES) {
            assert_eq!(find(name), Some(offset));
        }
        assert_eq!(find(&same[MAX_COMPARES]), None, "held, past the cap");
        assert_eq!(find(&same[MAX_COMPARES + 1]), None, "never added");
    }

    /// A table of `names`, added in turn as if written one after the other after a header, and what was written.
    fn table_of(names: &[Name<'_>], seed: u64) -> (NameTable, Vec<u8>) {
        let mut written = vec![0; HEADER_LEN];
        let mut table = NameTable::with_seed(seed);
        for name in names {
            let offset = u16::try_from(written.len()).unwrap();
            assert!(table.add(offset, hash_of(name, seed)));
            written.extend(wire_of(name));
        }
        (table, written)
    }

    /// The names `n0.`, `n1.`... and the hashes the table keys them on.
    fn numbered(seed: u64) -> impl Iterator<Item = (Name<'static>, u32)> {
        (0..).map(move |i| {
            let name = name_of(&[format!("n{i}").as_bytes()]);
            let hash = hash_of(&name, seed);
            (name, hash)
        })
    }

    /// Names past a full group go to the next one, from the last group round to the first, and are found there.
    #[test]
    fn names_past_a_full_group_are_found_in_the_next() {
        const SEED: u64 = 1;
        // The last group: the top 5 bits of the hash all set.
        let names: Vec<_> = numbered(SEED)
            .filter(|&(_, hash)| hash >> 27 == u32::MAX >> 27)
            .map(|(name, _)| name)
            .take(GROUP + 2)
            .collect();
        let (table, written) = table_of(&names, SEED);
        for name in &names {
            let found = table.find(&written, &wire_of(name), hash_of(name, SEED));
            assert!(found.is_some(), "{name}");
        }
    }

    /// Names of one tag and of other homes are each found in their own group, more of them than a lookup compares.
    #[test]
    fn names_of_one_tag_in_other_groups_are_each_found() {
        const SEED: u64 = 1;
        let mut buckets = std::collections::HashMap::<u8, Vec<(u32, Name<'static>)>>::new();
        let names = numbered(SEED)
            .find_map(|(name, hash)| {
                // The home: the top 5 bits of the hash.
                let home = hash >> 27;
                let bucket = buckets.entry(NameTable::tag(hash)).or_default();
                if bucket.iter().all(|&(other, _)| other != home) {
                    bucket.push((home, name));
                }
                (bucket.len() > MAX_COMPARES).then(|| {
                    bucket
                        .iter()
                        .map(|(_, name)| name.clone())
                        .collect::<Vec<_>>()
                })
            })
            .unwrap();
        let (table, written) = table_of(&names, SEED);
        for name in &names {
            let found = table.find(&written, &wire_of(name), hash_of(name, SEED));
            assert!(found.is_some(), "{name}");
        }
    }

    /// Labels longer than a word that differ only in their last byte hash apart: written again, each is a pointer.
    #[test]
    fn long_labels_that_differ_at_their_end_are_each_pointed_to() {
        let names: Vec<_> = (0..=MAX_COMPARES)
            .map(|i| name_of(&[format!("abcdefghij{i}").as_bytes()]))
            .collect();
        let once = compressed(&names).len();
        let twice = compressed(&[names.clone(), names.clone()].concat()).len();
        assert_eq!(twice - once, 2 * names.len());
    }

    /// A rolled-back name is forgotten and frees its room in the table; the names before the cut stay found.
    #[test]
    fn a_rolled_back_name_frees_its_room() {
        const SEED: u64 = 1;
        let names: Vec<_> = numbered(SEED).map(|(name, _)| name).take(220).collect();
        let (kept, cut, after) = (&names[..50], &names[50..100], &names[100..]);
        assert!(kept.len() + cut.len() + after.len() > TABLE_CAPACITY);
        assert!(kept.len() + after.len() <= TABLE_CAPACITY);
        let mut buf = [0; 4096];
        let mut w = Writer::with_names(&mut buf, Some(NameTable::with_seed(SEED)));
        w.put_bytes(&[0; HEADER_LEN]).unwrap();
        for name in kept {
            w.put_name_compressed(name).unwrap();
        }
        let at = w.len();
        for name in cut {
            w.put_name_compressed(name).unwrap();
        }
        w.truncate(at);
        for name in after {
            w.put_name_compressed(name).unwrap();
        }
        let before = w.len();
        for name in kept.iter().chain(after) {
            w.put_name_compressed(name).unwrap();
        }
        assert_eq!(
            w.len() - before,
            2 * (kept.len() + after.len()),
            "a pointer each"
        );
    }

    /// Labels that differ by bits chosen to cancel in a multiplicative hash of the words of a name (the
    /// shape `flips` of the `message` bench has) hash apart, whatever the seed.
    #[test]
    fn flipped_bits_do_not_cancel() {
        for seed in [0, 1, 0x9E37_79B9_7F4A_7C15] {
            let hashes: std::collections::HashSet<u32> = (0..128_u32)
                .map(|variant| {
                    let mut label = [b'x'; 63];
                    for pair in (0..7).filter(|pair| variant >> pair & 1 == 1) {
                        label[8 * pair + 6] ^= 0x80;
                        label[8 * pair + 7] ^= 0x10;
                    }
                    hash_of(&name_of(&[label.as_slice(), b"example", b"com"]), seed)
                })
                .collect();
            assert_eq!(hashes.len(), 128, "seed {seed}");
        }
    }

    /// A name that has more labels before the shared ones than are looked up longest first still finds its
    /// longest suffix, by the search over the rest.
    #[test]
    fn deep_names_find_their_longest_suffix() {
        let shared: Vec<&[u8]> = [b"a".as_slice()]
            .repeat(30)
            .into_iter()
            .chain([b"com".as_slice()])
            .collect();
        let base = name_of(&shared);
        let base_len = wire_of(&base).len();
        for fresh in [1, LONGEST_FIRST, LONGEST_FIRST + 1, 12, 60] {
            let labels: Vec<&[u8]> = [b"bb".as_slice()]
                .repeat(fresh)
                .into_iter()
                .chain(shared.iter().copied())
                .collect();
            let written = compressed(&[base.clone(), name_of(&labels)]);
            assert_eq!(written.len(), base_len + 3 * fresh + 2, "{fresh} fresh");
            assert_eq!(
                written.get(written.len() - 2..),
                Some(&[0xC0, u8::try_from(HEADER_LEN).unwrap()][..]),
                "{fresh} fresh"
            );
        }
    }

    /// Past the table's capacity the suffixes kept are the shortest of a name, so those found last stay found.
    #[test]
    fn a_full_table_keeps_the_shortest_suffixes() {
        let deep = |label: &[u8]| name_of(&[label].repeat(127));
        let tail = name_of(&[b"b".as_slice()].repeat(50));
        let (a, b) = (deep(b"a"), deep(b"b"));
        let before = compressed(&[a.clone(), b.clone()]).len();
        let after = compressed(&[a, b, tail]).len();
        assert_eq!(
            after - before,
            2,
            "a pointer to the last 50 labels of the second"
        );
    }

    /// A name that starts where a pointer reaches and ends past it is remembered by its suffixes that a pointer
    /// reaches; one that starts past it is not remembered.
    #[test]
    fn names_past_what_a_pointer_reaches_are_not_remembered() {
        let name = name_of(&[b"cccc".as_slice()].repeat(10));
        let other = name_of(&[b"dddd".as_slice()].repeat(3));
        let (len, other_len) = (wire_of(&name).len(), wire_of(&other).len());
        let before = POINTER_LIMIT - 40;
        let mut buf = vec![0; POINTER_LIMIT + 200];
        let mut w = Writer::new(&mut buf);
        w.put_bytes(&vec![0; before]).unwrap();
        w.put_name_compressed(&name).unwrap();
        assert_eq!(
            w.len(),
            before + len,
            "8 of its 10 suffixes start below the limit"
        );
        w.put_name_compressed(&name).unwrap();
        assert_eq!(w.len(), before + len + 2, "a pointer to the first");
        let after = w.len();
        w.put_name_compressed(&other).unwrap();
        w.put_name_compressed(&other).unwrap();
        assert_eq!(w.len(), after + 2 * other_len, "written in full both times");
    }
}
