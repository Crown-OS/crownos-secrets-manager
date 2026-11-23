use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming};
use secrets_core::{ScrubStream, Scrubber};

/// A response body that goes through the scrubber as it streams. Trailers are dropped, because
/// they could carry a value past the scrubber.
pub(crate) struct ScrubbedBody {
    inner: Incoming,
    stream: Option<ScrubStream<Arc<Scrubber>>>,
}

impl ScrubbedBody {
    pub(crate) fn new(inner: Incoming, scrubber: Arc<Scrubber>) -> Self {
        Self {
            inner,
            stream: Some(ScrubStream::new(scrubber)),
        }
    }
}

impl Body for ScrubbedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        loop {
            if this.stream.is_none() {
                return Poll::Ready(None);
            }
            let frame = match Pin::new(&mut this.inner).poll_frame(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(frame) => frame,
            };
            let mut output = Vec::new();
            match frame {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if let Some(stream) = this.stream.as_mut() {
                        stream.push(&data, &mut output);
                    }
                }
                Some(Err(error)) => return Poll::Ready(Some(Err(error))),
                None => {
                    if let Some(stream) = this.stream.take() {
                        stream.finish(&mut output);
                    }
                }
            }
            if !output.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from(output)))));
            }
        }
    }
}
