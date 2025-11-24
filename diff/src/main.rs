use std::fs;

fn fname_to_lines(fname: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in fs::read_to_string(fname).unwrap().lines() {
        lines.push(String::from(line));
    }
    lines
}

/// Build the LCS DP table for two vectors of strings
fn lcs_table(a: &Vec<String>, b: &Vec<String>) -> Vec<Vec<usize>> {
    let n = a.len();
    let m = b.len();

    let mut dp = vec![vec![0; m + 1]; n + 1];

    for i in 0..n {
        for j in 0..m {
            if a[i] == b[j] {
                dp[i + 1][j + 1] = dp[i][j] + 1;
            } else {
                dp[i + 1][j + 1] = dp[i + 1][j].max(dp[i][j + 1]);
            }
        }
    }
    dp
}

/// Backtrack through DP table and produce diff ops
#[derive(Debug)]
enum DiffOp {
    Add(usize, String),     // line number in right file, content
    Del(usize, String),     // line number in left file
    Same(String),
    Change(usize, usize, String, String),
}

fn diff(a: Vec<String>, b: Vec<String>) -> Vec<DiffOp> {
    let dp = lcs_table(&a, &b);

    let mut ops: Vec<DiffOp> = Vec::new();

    let mut i = a.len();
    let mut j = b.len();

    while i > 0 || j > 0 {
        if i > 0 && j > 0 && a[i - 1] == b[j - 1] {
            ops.push(DiffOp::Same(a[i - 1].clone()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            ops.push(DiffOp::Add(j, b[j - 1].clone()));
            j -= 1;
        } else {
            ops.push(DiffOp::Del(i, a[i - 1].clone()));
            i -= 1;
        }
    }

    ops.reverse();
    ops
}

/// Render diff in a human-readable format (not strictly POSIX diff)
fn render_diff(ops: Vec<DiffOp>) -> String {
    let mut result = String::new();

    for op in ops {
        match op {
            DiffOp::Same(_) => {}
            DiffOp::Add(rn, line) => {
                result.push_str(&format!("{}a {}\n> {}\n", rn - 1, rn, line));
            }
            DiffOp::Del(ln, line) => {
                result.push_str(&format!("{}d {}\n< {}\n", ln, ln - 1, line));
            }
            DiffOp::Change(l, r, left, right) => {
                result.push_str(&format!("{}c{}\n< {}\n---\n> {}\n", l, r, left, right));
            }
        }
    }

    result
}

fn main() {
    let left = fname_to_lines("cal.txt");
    let right = fname_to_lines("vin.txt");

    let ops = diff(left, right);
    let out = render_diff(ops);

    println!("{}", out);
}
