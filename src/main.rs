use std::collections::HashMap;
use std::io::{self, BufRead};

#[derive(Debug)]
struct Node {
    data: String,
    next: Vec<String>, // postrequisites
}

fn main() {
    let stdin = io::stdin();
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    let mut prereqs: HashMap<String, Vec<String>> = HashMap::new();

    println!("Enter edges (format: A:B), terminate with empty line:");

    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            break;
        }
        // Split the edge "A:B"
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 {
            continue;
        }
        let from = parts[0].to_string();
        let to = parts[1].to_string();

        // Record the postrequisite (graph)
        graph.entry(from.clone()).or_insert_with(Vec::new).push(to.clone());

        // Record the prerequisites
        prereqs.entry(to.clone()).or_insert_with(Vec::new).push(from.clone());

        // Ensure every node exists in graph
        graph.entry(to.clone()).or_insert_with(Vec::new);
    }

    // Print the DAG as "course requires prereqs"
    for (course, pre) in prereqs.iter() {
        println!("{} requires {}", course, pre.join(","));
    }
}

