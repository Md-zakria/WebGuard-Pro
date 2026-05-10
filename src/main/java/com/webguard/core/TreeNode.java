package com.webguard.core;

import java.util.ArrayList;
import java.util.List;

/**
 * TreeNode<T>
 *
 * Generic N-ary tree node used to build the Attack Tree in ExploitDashboard.
 * Each node holds a label (display name) and a data payload of type T.
 *
 * Data Structure: N-ary Tree
 * Used in: AttackTree, ExploitDashboard (visual rendering)
 *
 * CSC211 Data Structures — WebGuard Pro
 */
public class TreeNode<T> {

    private String label;       // display text shown in the tree visual
    private T data;             // payload — e.g. exploit result string
    private String nodeType;    // "root", "module", "finding", "credential"
    private List<TreeNode<T>> children;

    public TreeNode(String label, T data, String nodeType) {
        this.label    = label;
        this.data     = data;
        this.nodeType = nodeType;
        this.children = new ArrayList<>();
    }

    /** Add a child node and return it for chaining */
    public TreeNode<T> addChild(String childLabel, T childData, String childType) {
        TreeNode<T> child = new TreeNode<>(childLabel, childData, childType);
        children.add(child);
        return child;
    }

    /** Add a pre-built child node */
    public void addChild(TreeNode<T> child) {
        children.add(child);
    }

    /** DFS traversal — visits every node, calls visitor */
    public void dfs(java.util.function.Consumer<TreeNode<T>> visitor) {
        visitor.accept(this);
        for (TreeNode<T> child : children) {
            child.dfs(visitor);
        }
    }

    /** BFS traversal — level-order */
    public List<TreeNode<T>> bfs() {
        List<TreeNode<T>> result = new ArrayList<>();
        java.util.Queue<TreeNode<T>> queue = new java.util.LinkedList<>();
        queue.add(this);
        while (!queue.isEmpty()) {
            TreeNode<T> node = queue.poll();
            result.add(node);
            queue.addAll(node.children);
        }
        return result;
    }

    /** Total node count in this subtree */
    public int size() {
        int count = 1;
        for (TreeNode<T> child : children) count += child.size();
        return count;
    }

    /** Depth of this subtree */
    public int depth() {
        if (children.isEmpty()) return 0;
        int max = 0;
        for (TreeNode<T> child : children) max = Math.max(max, child.depth());
        return max + 1;
    }

    // Getters / Setters
    public String getLabel()               { return label; }
    public void setLabel(String label)     { this.label = label; }
    public T getData()                     { return data; }
    public void setData(T data)            { this.data = data; }
    public String getNodeType()            { return nodeType; }
    public List<TreeNode<T>> getChildren() { return children; }
    public boolean isLeaf()               { return children.isEmpty(); }

    @Override
    public String toString() {
        return "[" + nodeType + "] " + label;
    }
}
