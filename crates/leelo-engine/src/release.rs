//! This production gate checks context and order before credential release.
//! Cryptographic authentication and the monotonic clock are caller obligations.
use vstd::prelude::*;

verus! {

pub struct ReleaseState {
    context: [u8; 48],
    phase: u8,
    require_live: bool,
}

impl ReleaseState {
    pub closed spec fn context_value(&self) -> Seq<u8> { self.context@ }
    pub closed spec fn phase_value(&self) -> u8 { self.phase }
    pub closed spec fn needs_live(&self) -> bool { self.require_live }

    pub fn new(context: [u8; 48], require_live: bool) -> (result: Self)
        ensures result.context_value() == context@, result.phase_value() == 0,
            result.needs_live() == require_live,
    {
        Self { context, phase: 0, require_live }
    }

    /// The evidence must refer to every byte of this operation's context.
    fn matches(&self, context: &[u8; 48]) -> (result: bool)
        ensures result == (self.context@ == context@),
    {
        let mut i: usize = 0;
        while i < 48
            invariant i <= 48,
                forall|j: int| 0 <= j < i ==> #[trigger] self.context@[j] == context@[j],
            decreases 48 - i,
        {
            if self.context[i] != context[i] { return false; }
            i += 1;
        }
        assert(self.context@ =~= context@);
        true
    }

    fn advance(&mut self, context: &[u8; 48], expected: u8, live: bool) -> (accepted: bool)
        requires expected < 4,
        ensures
            accepted == (old(self).context@ == context@
                && old(self).phase == expected
                && (expected != 1 || !old(self).require_live || live)),
            final(self).context == old(self).context,
            final(self).require_live == old(self).require_live,
            final(self).phase == if accepted { (expected + 1) as u8 } else { old(self).phase },
    {
        if !self.matches(context) || self.phase != expected
            || (expected == 1 && self.require_live && !live)
        {
            return false;
        }
        self.phase = expected + 1;
        true
    }

    pub fn network(&mut self, context: &[u8; 48]) -> (accepted: bool)
        ensures accepted == (old(self).phase_value() == 0 && old(self).context_value() == context@),
            final(self).context_value() == old(self).context_value(), final(self).needs_live() == old(self).needs_live(),
            final(self).phase_value() == if accepted { 1 } else { old(self).phase_value() },
    { self.advance(context, 0, false) }

    pub fn tpm(&mut self, context: &[u8; 48], live: bool) -> (accepted: bool)
        ensures accepted == (old(self).phase_value() == 1 && old(self).context_value() == context@
                && (!old(self).needs_live() || live)),
            final(self).context_value() == old(self).context_value(), final(self).needs_live() == old(self).needs_live(),
            final(self).phase_value() == if accepted { 2 } else { old(self).phase_value() },
    { self.advance(context, 1, live) }

    pub fn payload(&mut self, context: &[u8; 48]) -> (accepted: bool)
        ensures accepted == (old(self).phase_value() == 2 && old(self).context_value() == context@),
            final(self).context_value() == old(self).context_value(), final(self).needs_live() == old(self).needs_live(),
            final(self).phase_value() == if accepted { 3 } else { old(self).phase_value() },
    { self.advance(context, 2, false) }

    pub fn release(&mut self, context: &[u8; 48], within_deadline: bool) -> (accepted: bool)
        ensures accepted == (old(self).phase_value() == 3 && old(self).context_value() == context@ && within_deadline),
            final(self).context_value() == old(self).context_value(), final(self).needs_live() == old(self).needs_live(),
            final(self).phase_value() == if accepted { 4 } else { old(self).phase_value() },
    {
        if !within_deadline { return false; }
        self.advance(context, 3, false)
    }
}

}

#[cfg(test)]
mod tests {
    use super::ReleaseState;

    #[test]
    fn evidence_needs_exact_context_order_freshness_and_one_release() {
        let context = [7; 48];
        for changed in 0..48 {
            let mut wrong = context;
            wrong[changed] ^= 1;
            let mut state = ReleaseState::new(context, true);
            assert!(!state.tpm(&context, true));
            assert!(!state.payload(&context));
            assert!(!state.release(&context, true));
            assert!(!state.network(&wrong));
            assert!(state.network(&context));
            assert!(!state.network(&context));
            assert!(!state.tpm(&wrong, true));
            assert!(!state.tpm(&context, false));
            assert!(state.tpm(&context, true));
            assert!(!state.payload(&wrong));
            assert!(state.payload(&context));
            assert!(!state.release(&wrong, true));
            assert!(!state.release(&context, false));
            assert!(state.release(&context, true));
            assert!(!state.release(&context, true));
        }
    }
}
