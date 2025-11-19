type Heap<T> = Vec<T>;

fn heapify<T>(mut h: Heap<T>, i: usize, gt: fn(&T, &T) -> bool) -> Heap<T> {
    // sift-down the element at index i within the full heap `h`
    let len = h.len();
    if len == 0 || i >= len {
        return h;
    }

    let mut root = i;
    loop {
        let left = 2 * root + 1;
        let right = left + 1;
        let mut swap_idx = root;

        if left < len && gt(&h[left], &h[swap_idx]) {
            swap_idx = left;
        }
        if right < len && gt(&h[right], &h[swap_idx]) {
            swap_idx = right;
        }

        if swap_idx == root {
            break;
        }

        h.swap(root, swap_idx);
        root = swap_idx;
    }

    h
}

fn reheapify<T>(mut h: Heap<T>, mut i: usize, gt: fn(&T, &T) -> bool) -> Heap<T> {
    // sift-up the element at index i
    while i > 0 {
        let parent = (i - 1) / 2;
        if gt(&h[i], &h[parent]) {
            h.swap(i, parent);
            i = parent;
        } else {
            break;
        }
    }
    h
}

fn vec_to_heap<T>(mut xs: Vec<T>, gt: fn(&T, &T) -> bool) -> Heap<T> {
    // Build heap in-place: heapify all non-leaf nodes from right to left.
    let n = xs.len();
    if n <= 1 {
        return xs;
    }
    // last parent is at n/2 - 1; iterate 0..n/2 then rev to get (n/2-1 .. 0)
    for i in (0..n / 2).rev() {
        xs = heapify(xs, i, gt);
    }
    xs
}

fn heap_to_vec<T>(mut h: Heap<T>, gt: fn(&T, &T) -> bool) -> Vec<T> {
    // Repeatedly remove root (swap with last, pop) and sift-down new root.
    let mut out: Vec<T> = Vec::with_capacity(h.len());
    while !h.is_empty() {
        let last = h.len() - 1;
        h.swap(0, last);
        let popped = h.pop().unwrap();
        out.push(popped);
        if !h.is_empty() {
            h = heapify(h, 0, gt);
        }
    }
    out
}

fn hsort<T>(xs: Vec<T>, gt: fn(&T, &T) -> bool) -> Vec<T> {
    heap_to_vec(vec_to_heap(xs, gt), gt)
}

fn main() {
    let xs: Vec<u64> = vec![2, 4, 6, 8, 5, 3, 7];
    fn f(x: &u64, y: &u64) -> bool {
        return x > y; // max-heap
    }
    dbg!(&xs);
    let sorted: Vec<u64> = hsort(xs, f);
    dbg!(&sorted);
}

