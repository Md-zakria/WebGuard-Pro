package com.webguard.core;

import java.util.ArrayList;
import java.util.List;

/**
 * AttackTree
 *
 * N-ary tree that models the full exploit attack graph.
 * Root = target host. Children = exploit modules. Leaves = breached data.
 *
 * Structure:
 *   localhost:8080  (root)
 *   ├── SQL Injection  (module)
 *   │   ├── databases: dvwa, mysql  (finding)
 *   │   ├── users: admin, gordonb  (finding)
 *   │   └── admin:password  (credential)
 *   ├── XSS Injector  (module)
 *   │   └── <script>alert(1)</script> reflected  (finding)
 *   ├── Brute Force  (module)
 *   │   └── Valid login: admin:password  (credential)
 *   └── Dir Traversal  (module)
 *       ├── /dvwa/config/ [200]  (finding)
 *       └── /phpmyadmin/ [200]  (finding)
 *
 * Data Structures used: N-ary Tree, Queue (BFS), Stack (DFS)
 * CSC211 Data Structures — WebGuard Pro
 */
public class AttackTree {

    private TreeNode<String> root;
    private final List<Runnable> changeListeners = new ArrayList<>();

    public AttackTree(String targetHost) {
        this.root = new TreeNode<>(targetHost, targetHost, "root");
    }

    /** Add a top-level module node (SQLi, XSS, etc.) and return it */
    public TreeNode<String> addModule(String moduleName) {
        TreeNode<String> moduleNode = new TreeNode<>(moduleName, moduleName, "module");
        root.addChild(moduleNode);
        notifyListeners();
        return moduleNode;
    }

    /** Add a finding leaf under a module node */
    public void addFinding(TreeNode<String> moduleNode, String finding) {
        moduleNode.addChild(finding, finding, "finding");
        notifyListeners();
    }

    /** Add a credential leaf (special red highlight) under a module node */
    public void addCredential(TreeNode<String> moduleNode, String credential) {
        moduleNode.addChild(credential, credential, "credential");
        notifyListeners();
    }

    /** Add a path finding (directory traversal results) */
    public void addPath(TreeNode<String> moduleNode, String path) {
        moduleNode.addChild(path, path, "path");
        notifyListeners();
    }

    /** Get root node */
    public TreeNode<String> getRoot() { return root; }

    /** Total nodes in tree */
    public int totalNodes() { return root.size(); }

    /** All nodes via BFS — used for rendering */
    public List<TreeNode<String>> getAllNodesBFS() { return root.bfs(); }

    /** All module nodes (direct children of root) */
    public List<TreeNode<String>> getModules() { return root.getChildren(); }

    /** Reset tree to just the root */
    public void reset(String targetHost) {
        this.root = new TreeNode<>(targetHost, targetHost, "root");
        notifyListeners();
    }

    /** Register a listener to be called when tree changes — used by UI to re-render */
    public void addChangeListener(Runnable listener) {
        changeListeners.add(listener);
    }

    private void notifyListeners() {
        for (Runnable r : changeListeners) r.run();
    }

    /** Print tree to console for debugging */
    public void printTree() {
        printNode(root, "", true);
    }

    private void printNode(TreeNode<String> node, String prefix, boolean isLast) {
        System.out.println(prefix + (isLast ? "└── " : "├── ") + node.getLabel());
        List<TreeNode<String>> children = node.getChildren();
        for (int i = 0; i < children.size(); i++) {
            printNode(children.get(i), prefix + (isLast ? "    " : "│   "), i == children.size() - 1);
        }
    }
}
