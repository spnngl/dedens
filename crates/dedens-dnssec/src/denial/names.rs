//! Name arithmetic the proofs need and `dedens-proto` does not offer: canonical order and ancestors.

use core::cmp::Ordering;

use dedens_proto::{Name, NameError};
#[cfg(verus_only)]
use vstd::{prelude::*, std_specs::cmp::PartialOrdSpec};

/// The labels of `name`, least specific first, the order canonical comparison walks them in.
fn from_the_root<'n>(name: &'n Name<'_>) -> Vec<&'n [u8]> {
    let mut labels: Vec<&[u8]> = name.labels().collect();
    labels.reverse();
    labels
}

/// Canonical order of names (RFC 4034 §6.1): label by label from the root, each label as lowercase unsigned
/// bytes, a name that runs out of labels first.
pub(super) fn canonical_cmp(a: &Name<'_>, b: &Name<'_>) -> Ordering {
    let (a, b) = (from_the_root(a), from_the_root(b));
    a.iter()
        .zip(&b)
        .map(|(x, y)| {
            x.iter()
                .map(u8::to_ascii_lowercase)
                .cmp(y.iter().map(u8::to_ascii_lowercase))
        })
        .find(|ord| ord.is_ne())
        .unwrap_or_else(|| a.len().cmp(&b.len()))
}

/// A name ordered canonically, for [`covers`].
#[derive(Debug, Clone, Copy)]
pub(super) struct Canonical<'n>(pub(super) &'n Name<'n>);

impl PartialEq for Canonical<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Canonical<'_> {}

impl PartialOrd for Canonical<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Canonical<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        canonical_cmp(self.0, other.0)
    }
}

/// Whether a chain link from `owner` to `next` covers `name`: `name` sorts strictly between them. The last link
/// of a chain wraps to the first, so `next` does not sort after `owner` there (RFC 4034 §4.1.1, RFC 5155 §1.2).
///
/// Verus proves (D180) that in any chain, for any strict order, a name is covered by exactly one link, unless it
/// sorts alike an owner, which none covers: `one_link_covers`.
#[cfg_attr(verus_only, verus_spec(r =>
    ensures
        T::obeys_partial_cmp_spec() ==> r == link_covers(owner, next, name),
))]
pub(super) fn covers<T: Ord + ?Sized>(owner: &T, next: &T, name: &T) -> bool {
    if owner < next {
        owner < name && name < next
    } else {
        owner < name || name < next
    }
}

#[cfg(verus_only)]
verus! {

/// `a` sorts before `b`.
pub(super) open spec fn before<T: PartialOrd + ?Sized>(a: &T, b: &T) -> bool {
    a.partial_cmp_spec(b) == Some(Ordering::Less)
}

/// Neither sorts before the other: the same name, as far as the order goes.
spec fn alike<T: PartialOrd + ?Sized>(a: &T, b: &T) -> bool {
    !before(a, b) && !before(b, a)
}

/// [`covers`], in terms of [`before`].
pub(super) open spec fn link_covers<T: PartialOrd + ?Sized>(owner: &T, next: &T, name: &T) -> bool {
    if before(owner, next) {
        before(owner, name) && before(name, next)
    } else {
        before(owner, name) || before(name, next)
    }
}

/// [`before`] is a strict order: irreflexive and transitive. Canonical order (RFC 4034 §6.1) is one, by a proof
/// Verus does not make.
spec fn strict_order<T: PartialOrd + ?Sized>() -> bool {
    &&& forall|a: &T| !before(a, a)
    &&& forall|a: &T, b: &T, c: &T| #[trigger] before(a, b) && #[trigger] before(b, c) ==> before(a, c)
}

/// The owners of `chain` are in order.
spec fn in_order<T: PartialOrd + ?Sized>(chain: Seq<&T>) -> bool {
    forall|i: int| 0 <= i < chain.len() - 1 ==> before(chain[i], #[trigger] chain[i + 1])
}

/// The links of `chain`, each owner to the next and the last to the first, among the first `k` that cover `name`.
spec fn covering<T: PartialOrd + ?Sized>(chain: Seq<&T>, name: &T, k: int) -> nat
    decreases k,
{
    if k <= 0 {
        0
    } else {
        covering(chain, name, k - 1)
            + if link_covers(chain[k - 1], chain[k % (chain.len() as int)], name) { 1nat } else { 0nat }
    }
}

/// Some owner of `chain` sorts with `name`.
spec fn owned<T: PartialOrd + ?Sized>(chain: Seq<&T>, name: &T) -> bool {
    exists|i: int| 0 <= i < chain.len() && #[trigger] alike(chain[i], name)
}

/// `name` sorts strictly between the first and the `k`-th owner of `chain`, alike none up to the `k`-th.
spec fn between<T: PartialOrd + ?Sized>(chain: Seq<&T>, name: &T, k: int) -> bool {
    &&& before(chain[0], name)
    &&& before(name, chain[k])
    &&& forall|i: int| 0 <= i <= k ==> !#[trigger] alike(chain[i], name)
}

/// In a chain of owners in order, a name is covered by exactly one link, and an owner by none: what makes an NSEC
/// or NSEC3 chain prove that a name does not exist (RFC 4034 §4.1.1, RFC 5155 §1.2). For chains of any length.
proof fn one_link_covers<T: PartialOrd + ?Sized>(chain: Seq<&T>, name: &T)
    requires
        strict_order::<T>(),
        chain.len() >= 1,
        in_order(chain),
    ensures
        covering(chain, name, chain.len() as int) == if owned(chain, name) { 0nat } else { 1nat },
{
    let n = chain.len() as int;
    sorted_up_to(chain, n - 1);
    first_links(chain, name, n - 1);
    vstd::arithmetic::div_mod::lemma_mod_self_0(n);
    if owned(chain, name) {
        // Alike the j-th owner, it sorts neither after the last nor before the first: the last link misses it.
        let j = choose|j: int| 0 <= j < n && #[trigger] alike(chain[j], name);
        sorted_up_to(chain, j);
        if j < n - 1 {
            assert(before(chain[j], chain[n - 1]));
        }
        if j > 0 {
            assert(before(chain[0], chain[j]));
        }
        assert(!between(chain, name, n - 1));
    } else {
        // Alike neither the first owner nor the last: between them, or past either end, which the last link
        // covers.
        assert(!alike(chain[0], name) && !alike(chain[n - 1], name));
    }
}

/// The links but the last cover `name` once if it sorts between the first and the `k`-th owner, else never.
proof fn first_links<T: PartialOrd + ?Sized>(chain: Seq<&T>, name: &T, k: int)
    requires
        strict_order::<T>(),
        in_order(chain),
        0 <= k < chain.len(),
    ensures
        covering(chain, name, k) == if between(chain, name, k) { 1nat } else { 0nat },
    decreases k,
{
    if k > 0 {
        first_links(chain, name, k - 1);
        vstd::arithmetic::div_mod::lemma_small_mod(k as nat, chain.len());
        sorted_up_to(chain, k - 1);
        sorted_up_to(chain, k);
        next_in_order(chain, k - 1);
        if before(chain[k - 1], name) && before(name, chain[k]) {
            // The k-th link covers it: it sorts after the owners up to the link's, before the next.
            assert forall|i: int| 0 <= i <= k implies !#[trigger] alike(chain[i], name) by {
                if i < k - 1 {
                    assert(before(chain[i], chain[k - 1]));
                }
            }
            if k > 1 {
                assert(before(chain[0], chain[k - 1]));
            }
        } else if between(chain, name, k - 1) {
            // An earlier link covers it, and it sorts before the k-th owner too.
            assert(before(name, chain[k]));
        } else if between(chain, name, k) {
            // Then it sorts before the link's owner: an earlier link would cover it.
            assert(!alike(chain[k - 1], name));
            assert(between(chain, name, k - 1));
        }
    }
}

/// The `i`-th owner of a chain in order sorts before the next.
proof fn next_in_order<T: PartialOrd + ?Sized>(chain: Seq<&T>, i: int)
    requires
        in_order(chain),
        0 <= i < chain.len() - 1,
    ensures
        before(chain[i], chain[i + 1]),
{
}

/// The owners before the `j`-th of a chain in order sort before it.
proof fn sorted_up_to<T: PartialOrd + ?Sized>(chain: Seq<&T>, j: int)
    requires
        strict_order::<T>(),
        in_order(chain),
        0 <= j < chain.len(),
    ensures
        forall|i: int| 0 <= i < j ==> before(#[trigger] chain[i], chain[j]),
    decreases j,
{
    if j > 0 {
        sorted_up_to(chain, j - 1);
        next_in_order(chain, j - 1);
    }
}

} // verus!

/// How many labels, counted from the root, `a` and `b` share.
pub(super) fn shared_labels(a: &Name<'_>, b: &Name<'_>) -> usize {
    from_the_root(a)
        .iter()
        .zip(&from_the_root(b))
        .take_while(|(x, y)| x.eq_ignore_ascii_case(y))
        .count()
}

/// The last `count` labels of `name`: its ancestor of that depth, or `name` itself when it has no more.
///
/// # Errors
///
/// Never in practice, a suffix of a valid name being valid; kept as [`NameError`] so no caller needs a panic.
pub(super) fn suffix(name: &Name<'_>, count: usize) -> Result<Name<'static>, NameError> {
    Name::from_labels(name.labels().skip(name.label_count().saturating_sub(count)))
}

/// The wildcard `*.ancestor` (RFC 4592 §2.1.1).
///
/// # Errors
///
/// [`NameError::NameTooLong`] when `ancestor` leaves no room for the label: no such wildcard exists.
pub(super) fn wildcard(ancestor: &Name<'_>) -> Result<Name<'static>, NameError> {
    Name::from_labels(core::iter::once(&b"*"[..]).chain(ancestor.labels()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name<'static> {
        text.parse().expect("a valid name")
    }

    /// RFC 4034 §6.1: the example order, whose labels all differ only past the first byte, in case or in depth.
    #[test]
    fn rfc4034_canonical_order() {
        let sorted = [
            "example.",
            "a.example.",
            "yljkjljk.a.example.",
            "Z.a.example.",
            "zABC.a.EXAMPLE.",
            "z.example.",
            "\\001.z.example.",
            "*.z.example.",
            "\\200.z.example.",
        ]
        .map(name);
        for (i, a) in sorted.iter().enumerate() {
            for (j, b) in sorted.iter().enumerate() {
                assert_eq!(
                    Canonical(a).cmp(&Canonical(b)),
                    i.cmp(&j),
                    "{a} against {b}"
                );
            }
        }
    }

    #[test]
    fn root_sorts_first() {
        assert!(Canonical(&Name::root()) < Canonical(&name("a.")));
    }

    #[test]
    fn ancestors_and_wildcards() {
        let n = name("a.b.c.example.");
        assert_eq!(suffix(&n, 2).unwrap(), name("c.example."));
        assert_eq!(suffix(&n, 9).unwrap(), n);
        assert_eq!(wildcard(&name("c.example.")).unwrap(), name("*.c.example."));
        assert_eq!(shared_labels(&n, &name("x.C.example.")), 2);
    }

    #[test]
    fn a_link_covers_the_names_between_and_the_wrap() {
        assert!(covers(&1, &5, &3));
        assert!(!covers(&1, &5, &1));
        assert!(!covers(&1, &5, &5));
        assert!(!covers(&1, &5, &7));
        // The last link, 7 to 2, wraps.
        assert!(covers(&7, &2, &9) && covers(&7, &2, &1));
        assert!(!covers(&7, &2, &5) && !covers(&7, &2, &2) && !covers(&7, &2, &7));
        // The only link of a chain covers all but its owner.
        assert!(covers(&4, &4, &3) && covers(&4, &4, &5) && !covers(&4, &4, &4));
    }
}
