//! Name arithmetic the proofs need and `dedens-proto` does not offer: canonical order and ancestors.

use core::cmp::Ordering;

use dedens_proto::name::{Name, NameError};

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
pub(super) fn covers<T: Ord + ?Sized>(owner: &T, next: &T, name: &T) -> bool {
    if owner < next {
        owner < name && name < next
    } else {
        owner < name || name < next
    }
}

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
