pub mod threading {


use std::{sync::{mpsc, Arc, Mutex}, thread, collections::HashMap};
use log::*;

/**
 * For worker thread:
 * - receive TCP connection
 * - interpret HTTP/1.1 CONNECT request
 * - send job to main thread
 * - receive result from main thread
 * - proxy traffic: relay between TCP connection and main thread
 */

#[derive(PartialEq)]
enum EventType {
    Headers,
    Data,
    Datagram,
    Finished,
}

pub struct SendJob {
    stream_id: u64,
    send_type: EventType,
    data: Vec<u8>,
}

pub struct ReceiveJob {
    receive_type: EventType,
    data: Vec<u8>,
}

struct Worker<R> {
    stream_id: u64,
    sender: mpsc::Sender<R>,
    handle: thread::JoinHandle<()>,
}

pub struct ThreadPool<S, R> {
    workers: HashMap<u64, Worker<R>>,
    receiver: mpsc::Receiver<S>,
    sender: Arc<Mutex<mpsc::Sender<S>>>,
}

impl<R> Worker<R> {
    fn new(stream_id: u64, sender: mpsc::Sender<R>, worker_fn: impl FnOnce() -> () + std::marker::Send + 'static) -> Worker<R> {
        let handle = thread::spawn(worker_fn);

        Worker { stream_id, sender, handle }
    }
}

impl<S: std::marker::Send + 'static, R: std::marker::Send + 'static> ThreadPool<S, R> {
    pub fn new() -> ThreadPool<S, R> {
        let (sender, receiver) = mpsc::channel();

        let sender = Arc::new(Mutex::new(sender));

        let mut workers = HashMap::new();

        ThreadPool { workers, receiver, sender }
    }

    pub fn new_stream<F>(&mut self, stream_id: u64, f: F)
    where
        F: FnOnce(mpsc::Receiver<R>, Arc<Mutex<mpsc::Sender<S>>>) -> () + Send + 'static,
    {
        let send_job_sender = self.sender.clone();
        let (receive_job_sender, receive_job_receiver) = mpsc::channel();
    
        let stream_id_copy = stream_id.clone();

        let worker = Worker::new(stream_id, receive_job_sender, move || { 
            debug!("worker {} spawned", stream_id_copy);
            f(receive_job_receiver, send_job_sender) 
        });
        self.workers.insert(stream_id, worker);
    }

    // TODO: implement drop to gracefully exit and cleanup
}


}
