//use std::collections::VecDeque;
use bincode::serialize;
use crate::domain::transaction::{Transaction};


pub struct TransactionGenerator {
    padding: usize,
    transactions_per_block: usize,
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
        TransactionGenerator { padding: padding_size, transactions_per_block }
    }

    /*
    pub fn poll(&mut self, transactions_per_block: usize) -> Vec<Transaction> {
        (0..transactions_per_block).filter_map(|_| self.pool.pop_front()).collect()
    }
     */

    pub fn generate(&mut self) -> Vec<Transaction> {
        (0..self.transactions_per_block).map(|_| Transaction::new(self.padding)).collect()
    }
}
