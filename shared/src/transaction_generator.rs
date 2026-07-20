//use std::collections::VecDeque;
use bincode::serialize;
use rand::Rng;
use crate::domain::transaction::{Transaction};


pub struct TransactionGenerator {
    padding: usize,
    transactions_per_block: usize,
    // Monotonic per-transaction id, seeded randomly at construction so that
    // batches differ across nodes and across runs. Without this every node
    // produces byte-identical transactions, so all batches share one digest.
    next_id: u64,
    //pool: VecDeque<Transaction>,
}

impl TransactionGenerator {

    pub fn new(target_size: usize, transactions_per_block: usize) -> Self {
        let mut padding_size = 0;
        loop {
            let tx = Transaction::new(padding_size);
            let size = serialize(&tx).unwrap().len();
            if size >= target_size {
                break
            }
            padding_size += 1;
        }
        //let pool = (0..transactions_per_block * 10000).map(|_| Transaction::new(padding_size)).collect();
        let next_id = rand::thread_rng().gen::<u64>();
        TransactionGenerator { padding: padding_size, transactions_per_block, next_id }
    }

    /*
    pub fn poll(&mut self, transactions_per_block: usize) -> Vec<Transaction> {
        (0..transactions_per_block).filter_map(|_| self.pool.pop_front()).collect()
    }
     */

    pub fn generate(&mut self) -> Vec<Transaction> {
        (0..self.transactions_per_block).map(|_| {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            Transaction::with_id(self.padding, id)
        }).collect()
    }
}
