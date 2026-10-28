//! Stages built outside the core (D23, D54): a plugin answers a query from what it holds, or passes it on.

use core::fmt;

use dedens_proto::edns::InfoCode;
use dedens_proto::header::HEADER_LEN;
use dedens_proto::{EncodeError, Message, Name, Query, Question, Rcode, Record, RecordType};

/// A stage that answers from what it holds, at once, or passes the query to the next stage (D54). It runs on
/// every query reaching it, on every serving thread: [`Plugin::answer`] should not allocate.
pub trait Plugin: fmt::Debug + Send + Sync {
    /// The answer to `query`, which passed the core's checks and has a question, or `None` to pass it on.
    fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>>;
}

/// What a plugin answers.
#[derive(Debug, Clone, Copy)]
pub struct Answer<'p> {
    /// The reply's response code.
    pub rcode: Rcode,
    /// The answer section; none when `None`.
    pub records: Option<&'p Records>,
    /// Whether AA is set: the plugin holds the data for the name, as local knowledge (RFC 1035 §4.1.1, RFC 9499
    /// §6 "Authoritative server").
    pub authoritative: bool,
    /// An extended error for clients sending an OPT record (RFC 8914).
    pub error: Option<InfoCode>,
}

/// Answer records already in wire form, to follow the question of a reply as they are: the reply is written
/// without encoding them.
///
/// They are written once after a question for a name, so the compression pointers in them point into that
/// question or into themselves: they fit a reply to any question for the same name, in any case and of any type,
/// and to any question at all when their only name is their owner, the question's name.
#[derive(Clone, PartialEq, Eq)]
pub struct Records {
    wire: Box<[u8]>,
    count: u16,
}

impl Records {
    /// `records`, to answer a question for `name`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when they do not fit a message.
    pub fn new(name: &Name<'_>, records: &[Record<'_>]) -> Result<Self, EncodeError> {
        let question = Question::new(name.clone(), RecordType::A);
        let message = Message {
            questions: vec![question],
            answer: records.to_vec(),
            ..Message::default()
        };
        let wire = message.to_vec_without_edns()?;
        // The question: its name, type and class.
        let start = HEADER_LEN + name.wire_len() + 4;
        Ok(Self {
            wire: wire.get(start..).unwrap_or_default().into(),
            count: u16::try_from(records.len()).map_err(|_| EncodeError::BufferFull)?,
        })
    }

    /// The records' bytes, as they follow the question.
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// How many records there are.
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }
}

impl fmt::Debug for Records {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Records")
            .field("count", &self.count)
            .field("len", &self.wire.len())
            .finish()
    }
}
