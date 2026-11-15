//! The line of a serving thread's queries that wait for the validation allowance (D186): first come, first asked,
//! bounded. No I/O and no clock: a place keeps the [`Waker`] of the task holding it, woken when the place comes
//! first; that task asks [`Pipeline::unpark`](crate::Pipeline::unpark) and sleeps on its own runtime.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::poll_fn;
use std::task::{Poll, Waker};

/// The line of one serving thread, not shared with the others: the queries in it are the thread's tasks.
#[derive(Debug)]
pub struct Parking {
    /// The places taken, oldest first: the ticket of each, which grows, and the waker of the task waiting for its
    /// turn.
    line: RefCell<VecDeque<(u64, Option<Waker>)>>,
    places: usize,
    next: Cell<u64>,
}

impl Parking {
    /// A line of `places` at most, allocated at once.
    #[must_use]
    pub fn new(places: usize) -> Self {
        Self {
            line: RefCell::new(VecDeque::with_capacity(places)),
            places,
            next: Cell::new(0),
        }
    }

    /// A place at the end of the line; `None` when all the places are taken, and the query is shed (D186).
    pub fn enter(&self) -> Option<Place<'_>> {
        let mut line = self.line.borrow_mut();
        if line.len() >= self.places {
            return None;
        }
        let ticket = self.next.get();
        // A ticket a nanosecond would last 584 years.
        self.next.set(ticket + 1);
        line.push_back((ticket, None));
        Some(Place {
            parking: self,
            ticket,
        })
    }

    /// Whether a query waits in the line: a query admitted after it goes behind it
    /// ([`Pipeline::defer`](crate::Pipeline::defer)).
    #[must_use]
    pub fn waiting(&self) -> bool {
        !self.line.borrow().is_empty()
    }
}

/// A place in a [`Parking`] line, left when dropped: the next place, first then, is woken.
#[derive(Debug)]
#[must_use = "a place is left when dropped"]
pub struct Place<'a> {
    parking: &'a Parking,
    ticket: u64,
}

impl Place<'_> {
    /// Waits until this place is the first of the line: its query is the one to ask the pipeline for.
    pub async fn turn(&self) {
        poll_fn(|cx| {
            let mut line = self.parking.line.borrow_mut();
            let Ok(index) = line.binary_search_by_key(&self.ticket, |&(ticket, _)| ticket) else {
                // A place is in the line until dropped.
                return Poll::Ready(());
            };
            if index == 0 {
                return Poll::Ready(());
            }
            if let Some((_, waker)) = line.get_mut(index)
                && !waker
                    .as_ref()
                    .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                *waker = Some(cx.waker().clone());
            }
            Poll::Pending
        })
        .await;
    }
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        let next = {
            let mut line = self.parking.line.borrow_mut();
            match line.binary_search_by_key(&self.ticket, |&(ticket, _)| ticket) {
                Ok(0) => {
                    line.pop_front();
                    line.front_mut().and_then(|(_, waker)| waker.take())
                }
                Ok(index) => {
                    line.remove(index);
                    None
                }
                Err(_) => None,
            }
        };
        // Woken once the line is given back: the waker may run the task at once.
        if let Some(next) = next {
            next.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake};

    use super::*;

    /// A waker counting its wakes.
    #[derive(Default)]
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Whether `place`'s turn came, polled once with `count`'s waker.
    fn turn(place: &Place<'_>, count: &Arc<Count>) -> bool {
        let waker = Waker::from(Arc::clone(count));
        pin!(place.turn())
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    }

    /// D186: the places come first in the order they were taken, each woken when the one before leaves, and a place
    /// left from inside the line wakes no one.
    #[test]
    fn places_come_first_in_the_order_taken() {
        let parking = Parking::new(4);
        assert!(!parking.waiting());
        let (first, second, third) = (parking.enter(), parking.enter(), parking.enter());
        let (Some(first), Some(second), Some(third)) = (first, second, third) else {
            panic!("three places of four");
        };
        assert!(parking.waiting());
        let counts: [Arc<Count>; 3] = Default::default();
        assert!(turn(&first, &counts[0]));
        assert!(!turn(&second, &counts[1]) && !turn(&third, &counts[2]));
        drop(first);
        assert_eq!(
            counts[1].0.load(Ordering::Relaxed),
            1,
            "the second is woken"
        );
        assert_eq!(counts[2].0.load(Ordering::Relaxed), 0);
        assert!(turn(&second, &counts[1]) && !turn(&third, &counts[2]));
        let fourth = parking.enter().expect("a place left");
        drop(third);
        assert_eq!(counts[2].0.load(Ordering::Relaxed), 0, "no one is woken");
        drop(second);
        assert!(turn(&fourth, &Arc::default()));
        drop(fourth);
        assert!(!parking.waiting());
    }

    /// D186: a full line takes no one more until a place is left.
    #[test]
    fn a_full_line_refuses_the_newest() {
        let parking = Parking::new(2);
        let first = parking.enter().expect("a place");
        let _second = parking.enter().expect("a place");
        assert!(parking.enter().is_none());
        drop(first);
        assert!(parking.enter().is_some());
    }
}
