package com.webguard.core;

import java.util.ArrayList;
import java.util.List;

/**
 * MinHeap<T extends Comparable<T>>
 *
 * Custom generic Min-Heap implementation.
 * Used by VulnerabilityReport to maintain vulnerabilities sorted by CVSS score.
 * Since Vulnerability.compareTo() is inverted (higher CVSS = smaller), this
 * effectively acts as a MAX-heap for severity — highest severity at root.
 *
 * Operations:
 *   insert()   O(log n)
 *   peek()     O(1)   — highest severity finding
 *   poll()     O(log n)
 *   size()     O(1)
 *
 * DS Role: Non-linear — used in Red Team VulnerabilityReport
 */
public class MinHeap<T extends Comparable<T>> {

    private final List<T> heap = new ArrayList<>();

    public void insert(T item) {
        heap.add(item);
        bubbleUp(heap.size() - 1);
    }

    public T peek() {
        if (heap.isEmpty()) throw new IllegalStateException("Heap is empty");
        return heap.get(0);
    }

    public T poll() {
        if (heap.isEmpty()) throw new IllegalStateException("Heap is empty");
        T top = heap.get(0);
        int last = heap.size() - 1;
        heap.set(0, heap.get(last));
        heap.remove(last);
        if (!heap.isEmpty()) bubbleDown(0);
        return top;
    }

    public boolean isEmpty() { return heap.isEmpty(); }
    public int size()        { return heap.size(); }

    /** Returns all items in sorted order without destroying the heap */
    public List<T> drainSorted() {
        MinHeap<T> copy = new MinHeap<>();
        for (T item : heap) copy.insert(item);
        List<T> sorted = new ArrayList<>();
        while (!copy.isEmpty()) sorted.add(copy.poll());
        return sorted;
    }

    // ---- Internal heap operations ----

    private void bubbleUp(int i) {
        while (i > 0) {
            int parent = (i - 1) / 2;
            if (heap.get(i).compareTo(heap.get(parent)) < 0) {
                swap(i, parent);
                i = parent;
            } else break;
        }
    }

    private void bubbleDown(int i) {
        int size = heap.size();
        while (true) {
            int left  = 2 * i + 1;
            int right = 2 * i + 2;
            int smallest = i;
            if (left  < size && heap.get(left).compareTo(heap.get(smallest))  < 0) smallest = left;
            if (right < size && heap.get(right).compareTo(heap.get(smallest)) < 0) smallest = right;
            if (smallest != i) { swap(i, smallest); i = smallest; }
            else break;
        }
    }

    private void swap(int a, int b) {
        T tmp = heap.get(a);
        heap.set(a, heap.get(b));
        heap.set(b, tmp);
    }
}
