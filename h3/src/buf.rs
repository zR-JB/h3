use std::collections::VecDeque;
use std::io::IoSlice;

use bytes::{Buf, Bytes, BytesMut};

#[derive(Debug)]
pub(crate) struct BufList {
    bufs: VecDeque<BytesMut>,
}

impl BufList {
    pub(crate) fn new() -> Self {
        BufList {
            bufs: VecDeque::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn push<T: Buf>(&mut self, mut buf: T) {
        self.push_bytes(&mut buf);
    }

    pub fn cursor(&self) -> Cursor<'_> {
        Cursor {
            buf: self,
            pos_total: 0,
            index: 0,
            pos_front: 0,
        }
    }
}

impl BufList {
    pub fn take_first_chunk(&mut self) -> Option<Bytes> {
        self.bufs.pop_front().map(BytesMut::freeze)
    }

    pub fn take_chunk(&mut self, max_len: usize) -> Option<Bytes> {
        let chunk = self.bufs.front_mut().map(|chunk| {
            chunk
                .split_to(usize::min(max_len, chunk.remaining()))
                .freeze()
        });

        if let Some(front) = self.bufs.front() {
            if front.remaining() == 0 {
                let _ = self.bufs.pop_front();
            }
        }
        chunk
    }

    pub fn push_bytes<T>(&mut self, buf: &mut T)
    where
        T: Buf,
    {
        debug_assert!(buf.has_remaining());
        while buf.has_remaining() {
            if self
                .bufs
                .back()
                .is_none_or(|tail| tail.len() == tail.capacity())
            {
                self.bufs
                    .push_back(BytesMut::with_capacity(buf.remaining().clamp(4096, 16384)));
            }
            let tail = self.bufs.back_mut().unwrap();
            let count = (tail.capacity() - tail.len()).min(buf.chunk().len());
            tail.extend_from_slice(&buf.chunk()[..count]);
            buf.advance(count);
        }
    }
}

#[cfg(test)]
impl BufList {
    pub(crate) fn from<T: Buf>(b: T) -> Self {
        let mut buf = Self::new();
        buf.push(b);
        buf
    }
}

impl Buf for BufList {
    #[inline]
    fn remaining(&self) -> usize {
        self.bufs.iter().map(|buf| buf.remaining()).sum()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.bufs.front().map(Buf::chunk).unwrap_or_default()
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            {
                let front = &mut self.bufs[0];
                let rem = front.remaining();
                if rem > cnt {
                    front.advance(cnt);
                    return;
                } else {
                    front.advance(rem);
                    cnt -= rem;
                }
            }
            self.bufs.pop_front();
        }
    }

    #[inline]
    fn chunks_vectored<'t>(&'t self, dst: &mut [IoSlice<'t>]) -> usize {
        if dst.is_empty() {
            return 0;
        }
        let mut vecs = 0;
        for buf in &self.bufs {
            vecs += buf.chunks_vectored(&mut dst[vecs..]);
            if vecs == dst.len() {
                break;
            }
        }
        vecs
    }
}

pub struct Cursor<'a> {
    buf: &'a BufList,
    pos_total: usize, // position amongst all bytes
    pos_front: usize, // position in the current front buffer
    index: usize,     // current front buffer index
}

impl Cursor<'_> {
    pub fn position(&self) -> usize {
        self.pos_total
    }
}

impl Buf for Cursor<'_> {
    #[inline]
    fn remaining(&self) -> usize {
        self.buf.remaining() - self.pos_total
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.buf
            .bufs
            .get(self.index)
            .map(|buffer| &buffer.chunk()[self.pos_front..])
            .unwrap_or_default()
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.buf.remaining() - self.pos_total);
        while cnt > 0 {
            {
                let front = &self.buf.bufs[self.index];
                let rem = front.remaining() - self.pos_front;
                if rem > cnt {
                    self.pos_total += cnt;
                    self.pos_front += cnt;
                    return;
                } else {
                    self.pos_total += rem;
                    self.pos_front = 0;
                    cnt -= rem;
                }
            }
            self.index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn fragmented_receive_storage_is_owned_and_coalesced() {
        let backing = Bytes::from(vec![90; 2 * 1024 * 1024]);
        let mut buffers = BufList::new();
        for _ in 0..2048 {
            buffers.push_bytes(&mut backing.slice(..32));
        }
        assert!(buffers.bufs.len() <= 17, "retained one entry per fragment");
        let retained = buffers.chunk().as_ptr() as usize;
        let source = backing.as_ptr() as usize;
        assert!(!(source..source + backing.len()).contains(&retained));
        assert_eq!(buffers.remaining(), 64 * 1024);
        let mut received = Vec::new();
        while let Some(chunk) = buffers.take_chunk(1000) {
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received, vec![90; 64 * 1024]);
    }

    #[test]
    fn cursor_advance() {
        let buf = BufList::from(Bytes::from_static(&[1u8, 2, 3, 4]));
        let mut cur = buf.cursor();
        cur.advance(2);
        assert_eq!(cur.remaining(), 2);
        let mut slices = [IoSlice::new(&[])];
        assert_eq!(cur.chunks_vectored(&mut slices), 1);
        assert_eq!(&*slices[0], &[3, 4]);
        cur.advance(2);
        assert_eq!(cur.remaining(), 0);
        assert!(cur.chunk().is_empty());
    }
}
