//! UNQ stage machinery (SPEC §5.8): per-invocation collision domain,
//! streaming-safe — outputs are uniquified in arrival order; deterministic
//! for a fixed input order. Consumed by `fs::plan`, `extract`, and the
//! strings CLI mode; the LEN stage's `cut_at_boundary` is shared from the
//! crate root.

use crate::cut_at_boundary;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UniqueStyle {
    Infix,
    Prefix,
    Postfix,
}

/// No uniquified variant of the name fits `max_bytes`.
#[derive(Debug)]
pub struct UniquifyError;

/// Per-invocation collision domain, streaming-safe (SPEC §5.8): outputs are
/// uniquified in arrival order; deterministic for a fixed input order.
pub struct Uniquifier {
    style: UniqueStyle,
    max_bytes: usize,
    seen: std::collections::HashSet<String>,
    next: std::collections::HashMap<String, usize>,
}

impl Uniquifier {
    pub fn new(style: UniqueStyle, max_bytes: usize) -> Self {
        Uniquifier {
            style,
            max_bytes,
            seen: std::collections::HashSet::new(),
            next: std::collections::HashMap::new(),
        }
    }

    /// Ok((name, uniquified?)); Err(UniquifyError) when no uniquified variant
    /// fits `max_bytes` (tag + extension leave no room for a stem char).
    pub fn apply(&mut self, name: String) -> Result<(String, bool), UniquifyError> {
        if self.seen.insert(name.clone()) {
            return Ok((name, false));
        }
        let mut n = *self.next.get(&name).unwrap_or(&1);
        loop {
            match self.candidate(&name, n) {
                Some(candidate) if self.seen.insert(candidate.clone()) => {
                    self.next.insert(name, n + 1);
                    return Ok((candidate, true));
                }
                Some(_) => n += 1, // collided with another base's output
                None => return Err(UniquifyError),
            }
        }
    }

    /// stem + `_n` + ext with the stem cut so the WHOLE fits `max_bytes`.
    /// The tag always survives; only the stem shrinks. Terminates: distinct n
    /// give distinct tags, and shrinking budgets hit zero → None.
    fn candidate(&self, base: &str, n: usize) -> Option<String> {
        let tag = format!("_{n}");
        let (stem, ext) = match base.rfind('.') {
            Some(0) | None => (base, ""),
            Some(i) => (&base[..i], &base[i..]),
        };
        let budget = self
            .max_bytes
            .saturating_sub(tag.len() + ext.len());
        if budget == 0 {
            return None;
        }
        let cut = cut_at_boundary(stem, budget);
        if cut.is_empty() {
            return None;
        }
        Some(match self.style {
            UniqueStyle::Infix => format!("{cut}{tag}{ext}"),
            UniqueStyle::Prefix => format!("{tag}{cut}{ext}"),
            UniqueStyle::Postfix => format!("{cut}{ext}{tag}"),
        })
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn uniquifier_infix_and_deterministic() {
        let mut u = Uniquifier::new(UniqueStyle::Infix, 255);
        assert_eq!(u.apply("report.pdf".into()).unwrap().0, "report.pdf");
        assert_eq!(u.apply("report.pdf".into()).unwrap().0, "report_1.pdf");
        assert_eq!(u.apply("report.pdf".into()).unwrap().0, "report_2.pdf");
    }

    #[test]
    fn uniquifier_respects_cap() {
        let mut u = Uniquifier::new(UniqueStyle::Infix, 12);
        let (n, _) = u.apply("abcdefgh.pdf".into()).unwrap();
        let (n2, _) = u.apply("abcdefgh.pdf".into()).unwrap();
        assert!(n.len() <= 12, "{n}");
        assert!(n2.len() <= 12, "{n2}");
    }
}
