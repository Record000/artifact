#!/usr/bin/env python3
"""
RPKI Repository Visualization Tool

This tool provides a visual representation of the RPKI repository structure,
showing the CA hierarchy and all associated objects (certificates, manifests,
CRLs, ROAs) in a tree-like format.

Usage:
    python visualize_repo.py <repo_directory>
    python visualize_repo.py <repo_directory> --mode stats
"""

import os
import sys
import argparse
from typing import List, Dict, Optional, Set
from pathlib import Path


# ============================================================================
# Tree Visualization Classes
# ============================================================================

class RepoNode:
    """Represents a node in the repository tree."""
    
    def __init__(self, name: str, path: str, node_type: str = "ca"):
        self.name = name
        self.path = path
        self.node_type = node_type  # 'ca', 'cert', 'mft', 'crl', 'roa', 'dir'
        self.children: List['RepoNode'] = []
        self.metadata: Dict = {}
    
    def add_child(self, child: 'RepoNode') -> None:
        """Add a child node."""
        self.children.append(child)
    
    def is_leaf(self) -> bool:
        """Check if this node has no children."""
        return len(self.children) == 0


class RepoTreeBuilder:
    """Builds a tree representation of an RPKI repository."""
    
    # RPKI file extensions
    CA_EXTENSIONS = ['.cer']
    MFT_EXTENSIONS = ['.mft']
    CRL_EXTENSIONS = ['.crl']
    ROA_EXTENSIONS = ['.roa']
    
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        self.root: Optional[RepoNode] = None
        self.processed_dirs: Set[str] = set()
    
    def build(self) -> RepoNode:
        """Build the repository tree."""
        # Create a root node representing the repository
        repo_name = os.path.basename(self.repo_path)
        self.root = RepoNode(repo_name, self.repo_path, 'ca')
        
        # Scan the repository
        self._scan_directory(self.root, self.repo_path, 0)
        
        return self.root
    
    def _scan_directory(self, parent_node: RepoNode, dir_path: str, depth: int) -> None:
        """
        Scan a directory and build the tree.
        
        RPKI repositories can have various structures:
        1. Root certificate + subdirectories for child CAs
        2. Only subdirectories (no root certificate at top level)
        3. Flat structure with all files in one directory
        """
        if not os.path.isdir(dir_path):
            return
        
        if dir_path in self.processed_dirs:
            return
        self.processed_dirs.add(dir_path)
        
        try:
            entries = sorted(os.listdir(dir_path))
        except PermissionError:
            return
        
        # Separate files and directories
        files = []
        dirs = []
        
        for entry in entries:
            entry_path = os.path.join(dir_path, entry)
            if os.path.isfile(entry_path):
                files.append((entry, entry_path))
            elif os.path.isdir(entry_path):
                dirs.append((entry, entry_path))
        
        # First, find root certificate (if any)
        root_cert = None
        for filename, filepath in files:
            if filename == 'root.cer' or (filename.endswith('.cer') and 
                                        not any(c[0].startswith(filename[:-4] + '/') for c in dirs)):
                root_cert = (filename, filepath)
                break
        
        # If we found a root certificate, add it as a child
        if root_cert:
            cert_name = os.path.splitext(root_cert[0])[0]
            cert_node = RepoNode(cert_name, root_cert[1], 'cert')
            parent_node.add_child(cert_node)
        
        # Process directories - they could be CA directories
        for dirname, dirpath in dirs:
            # Check if this directory contains CA certificates
            has_ca_cert = self._has_ca_cert(dirpath)
            
            if has_ca_cert:
                # This is a CA directory
                ca_node = RepoNode(dirname, dirpath, 'ca')
                parent_node.add_child(ca_node)
                self._scan_directory(ca_node, dirpath, depth + 1)
            else:
                # This might be a subdirectory with more structure
                # Check if it has subdirectories
                subdirs = [d for d in os.listdir(dirpath) if os.path.isdir(os.path.join(dirpath, d))]
                if subdirs:
                    # Recursively scan
                    dir_node = RepoNode(dirname, dirpath, 'dir')
                    parent_node.add_child(dir_node)
                    self._scan_directory(dir_node, dirpath, depth + 1)
                else:
                    # Leaf directory, scan for files
                    self._scan_files_in_dir(parent_node, dirpath)
        
        # Process remaining files (MFT, CRL, ROA, other certs)
        self._scan_files_in_dir(parent_node, dir_path, skip_root_cert=bool(root_cert))
    
    def _has_ca_cert(self, dir_path: str) -> bool:
        """Check if directory contains a CA certificate."""
        try:
            for filename in os.listdir(dir_path):
                if filename.endswith('.cer'):
                    return True
        except PermissionError:
            pass
        return False
    
    def _scan_files_in_dir(self, parent_node: RepoNode, dir_path: str, 
                          skip_root_cert: bool = False) -> None:
        """Scan a directory for RPKI files and add them as children."""
        try:
            entries = sorted(os.listdir(dir_path))
        except PermissionError:
            return
        
        for entry in entries:
            entry_path = os.path.join(dir_path, entry)
            if not os.path.isfile(entry_path):
                continue
            
            ext = os.path.splitext(entry)[1].lower()
            
            # Skip root certificate if requested
            if skip_root_cert and entry == 'root.cer':
                continue
            
            # Determine file type
            if ext in self.MFT_EXTENSIONS:
                file_node = RepoNode(entry, entry_path, 'mft')
                parent_node.add_child(file_node)
            elif ext in self.CRL_EXTENSIONS:
                file_node = RepoNode(entry, entry_path, 'crl')
                parent_node.add_child(file_node)
            elif ext in self.ROA_EXTENSIONS:
                file_node = RepoNode(entry, entry_path, 'roa')
                parent_node.add_child(file_node)
            elif ext in self.CA_EXTENSIONS:
                # Only add if not already added as root cert
                if not any(c.name == os.path.splitext(entry)[0] and c.node_type == 'cert' 
                          for c in parent_node.children):
                    file_node = RepoNode(entry, entry_path, 'cert')
                    parent_node.add_child(file_node)


class RepoTreePrinter:
    """Prints the repository tree in various formats."""
    
    # Unicode box-drawing characters
    BOX_CHARS = {
        'vertical': '│',
        'horizontal': '─',
        'corner_right': '└',
        'corner_left': '┌',
        'tee': '├',
        'cross': '┼',
    }
    
    # ASCII fallback characters
    ASCII_CHARS = {
        'vertical': '|',
        'horizontal': '-',
        'corner_right': '`',
        'corner_left': '/',
        'tee': '+',
        'cross': '+',
    }
    
    # Icons for different node types
    ICONS = {
        'ca': '🔐',
        'cert': '📜',
        'mft': '📋',
        'crl': '🚫',
        'roa': '🌐',
        'dir': '📁',
    }
    
    def __init__(self, use_unicode: bool = True, use_icons: bool = True):
        self.chars = self.BOX_CHARS if use_unicode else self.ASCII_CHARS
        self.use_icons = use_icons
    
    def print_tree(self, root: RepoNode, show_metadata: bool = False, 
                   max_depth: int = 3, max_files: int = 10) -> None:
        """Print the repository tree."""
        print("RPKI Repository Structure")
        print("=" * 50)
        self._print_node(root, "", True, show_metadata, max_depth, max_files, 0)
    
    def _print_node(
        self,
        node: RepoNode,
        prefix: str,
        is_last: bool,
        show_metadata: bool,
        max_depth: int,
        max_files: int,
        current_depth: int
    ) -> None:
        """Print a node recursively."""
        # Build the connector
        if is_last:
            connector = self.chars['corner_right'] + self.chars['horizontal']
            child_prefix = prefix + "  "
        else:
            connector = self.chars['tee'] + self.chars['horizontal']
            child_prefix = prefix + self.chars['vertical'] + " "
        
        # Get icon
        icon = self.ICONS.get(node.node_type, '') if self.use_icons else ''
        
        # Build node label
        label = f"{icon} {node.name}"
        if show_metadata and node.metadata:
            meta_str = ", ".join(f"{k}={v}" for k, v in node.metadata.items())
            label += f" [{meta_str}]"
        
        # Print the node
        print(f"{prefix}{connector}{label}")
        
        # Check depth limit
        if current_depth >= max_depth and node.node_type == 'ca':
            remaining = len(node.children)
            if remaining > 0:
                print(f"{child_prefix}... ({remaining} more items, use --max-depth to see more)")
            return
        
        # Print children
        for i, child in enumerate(node.children):
            is_last_child = (i == len(node.children) - 1)
            
            # Limit file display for large directories
            if node.node_type == 'ca' and child.node_type != 'ca' and i >= max_files:
                remaining = len(node.children) - i
                print(f"{child_prefix}... ({remaining} more files)")
                break
            
            self._print_node(child, child_prefix, is_last_child, show_metadata, 
                          max_depth, max_files, current_depth + 1)


class RepoStatsCollector:
    """Collects statistics from the repository tree."""
    
    def __init__(self, root: RepoNode):
        self.root = root
        self.stats = {
            # Structure metrics
            'depth': 0,           # Maximum depth of the CA hierarchy
            'num_ca': 0,          # Total number of CAs
            'num_cert': 0,        # Total number of certificates
            'max_branch': 0,      # Maximum branching factor (max children per CA)
            'leaf_count': 0,      # Number of leaf CAs (CAs with no child CAs)
            # Quantity metrics
            'num_roa': 0,         # Total number of ROAs
            'num_mft': 0,         # Total number of manifests
            'num_crl': 0,         # Total number of CRLs
            # Additional info
            'total_dirs': 0,
            'ca_by_depth': {},
            'files_by_ca': {}
        }
    
    def collect(self) -> Dict:
        """Collect all statistics."""
        self._collect_node(self.root, 0)
        return self.stats
    
    def _collect_node(self, node: RepoNode, depth: int) -> None:
        """Collect statistics from a node."""
        # Update max depth
        self.stats['depth'] = max(self.stats['depth'], depth)
        
        # Count by type
        if node.node_type == 'ca':
            self.stats['num_ca'] += 1
            self.stats['ca_by_depth'][depth] = self.stats['ca_by_depth'].get(depth, 0) + 1
            
            # Count CA children (for branching factor and leaf detection)
            ca_children = [c for c in node.children if c.node_type == 'ca']
            num_ca_children = len(ca_children)
            
            # Update max_branch (maximum CA branching factor)
            self.stats['max_branch'] = max(self.stats['max_branch'], num_ca_children)
            
            # Check if leaf CA (no child CAs)
            if num_ca_children == 0:
                self.stats['leaf_count'] += 1
            
            # Count files for this CA
            file_counts = {
                'mft': 0,
                'crl': 0,
                'roa': 0,
                'cert': 0
            }
            for child in node.children:
                if child.node_type in file_counts:
                    file_counts[child.node_type] += 1
            self.stats['files_by_ca'][node.name] = file_counts
        elif node.node_type == 'dir':
            self.stats['total_dirs'] += 1
        else:
            # Count RPKI objects
            if node.node_type == 'cert':
                self.stats['num_cert'] += 1
            elif node.node_type == 'mft':
                self.stats['num_mft'] += 1
            elif node.node_type == 'crl':
                self.stats['num_crl'] += 1
            elif node.node_type == 'roa':
                self.stats['num_roa'] += 1
        
        # Recurse into children with incremented depth for CA nodes
        for child in node.children:
            if child.node_type == 'ca':
                self._collect_node(child, depth + 1)
            else:
                self._collect_node(child, depth)
    
    def print_stats(self) -> None:
        """Print the collected statistics."""
        print("RPKI Repository Statistics")
        print("=" * 50)
        
        # Structure metrics
        print("\n[Structure Metrics]")
        print(f"  depth:      {self.stats['depth']}")
        print(f"  num_ca:     {self.stats['num_ca']}")
        print(f"  num_cert:   {self.stats['num_cert']}")
        print(f"  max_branch: {self.stats['max_branch']}")
        print(f"  leaf_count: {self.stats['leaf_count']}")
        
        # Quantity metrics
        print("\n[Quantity Metrics]")
        print(f"  num_roa:    {self.stats['num_roa']}")
        print(f"  num_mft:    {self.stats['num_mft']}")
        print(f"  num_crl:    {self.stats['num_crl']}")
        print()
        
        # Print CAs by depth
        if self.stats['ca_by_depth']:
            print("CAs by Depth:")
            for depth in sorted(self.stats['ca_by_depth'].keys()):
                print(f"  Depth {depth}: {self.stats['ca_by_depth'][depth]} CA(s)")
            print()
        
        # Print files per CA (limit to first 10)
        print("Files per CA (showing first 10):")
        for i, (ca_name, counts) in enumerate(sorted(self.stats['files_by_ca'].items())):
            if i >= 10:
                print(f"  ... and {len(self.stats['files_by_ca']) - 10} more CAs")
                break
            print(f"  {ca_name}:")
            print(f"    MFTs: {counts['mft']}, CRLs: {counts['crl']}, ROAs: {counts['roa']}, Certs: {counts['cert']}")


# ============================================================================
# Direct Directory Scanner (Alternative Approach)
# ============================================================================

class DirectRepoScanner:
    """
    Scan repository directly without building a tree.
    Useful for quick statistics on large repositories.
    """
    
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
    
    def scan(self) -> Dict:
        """Scan the repository and return statistics."""
        stats = {
            # Structure metrics
            'depth': 0,           # Maximum depth of the CA hierarchy
            'num_ca': 0,          # Total number of CAs
            'num_cert': 0,        # Total number of certificates
            'max_branch': 0,      # Maximum branching factor (max CA children per CA)
            'leaf_count': 0,      # Number of leaf CAs (CAs with no child CAs)
            # Quantity metrics
            'num_roa': 0,         # Total number of ROAs
            'num_mft': 0,         # Total number of manifests
            'num_crl': 0,         # Total number of CRLs
            # Additional info
            'total_dirs': 0,
            'ca_by_depth': {},
            'structure': []
        }
        
        self._scan_directory(self.repo_path, 0, stats, "Root")
        
        return stats
    
    def _scan_directory(self, dir_path: str, depth: int, stats: Dict, ca_name: str) -> bool:
        """
        Scan a directory recursively.
        
        Returns True if this is a leaf CA (no child CAs).
        """
        stats['depth'] = max(stats['depth'], depth)
        
        if depth not in stats['ca_by_depth']:
            stats['ca_by_depth'][depth] = 0
        stats['ca_by_depth'][depth] += 1
        stats['num_ca'] += 1
        
        # Count files and child CAs
        file_counts = {'mft': 0, 'crl': 0, 'roa': 0, 'cert': 0}
        child_ca_count = 0
        
        try:
            entries = sorted(os.listdir(dir_path))
        except PermissionError:
            return True
        
        for entry in entries:
            entry_path = os.path.join(dir_path, entry)
            
            if os.path.isdir(entry_path):
                # Check if it's a CA directory
                if self._has_ca_cert(entry_path):
                    child_ca_count += 1
                    child_name = os.path.basename(entry_path)
                    self._scan_directory(entry_path, depth + 1, stats, child_name)
                else:
                    # It's a regular directory
                    stats['total_dirs'] += 1
            elif os.path.isfile(entry_path):
                ext = os.path.splitext(entry)[1].lower()
                if ext == '.cer':
                    file_counts['cert'] += 1
                    stats['num_cert'] += 1
                elif ext == '.mft':
                    file_counts['mft'] += 1
                    stats['num_mft'] += 1
                elif ext == '.crl':
                    file_counts['crl'] += 1
                    stats['num_crl'] += 1
                elif ext == '.roa':
                    file_counts['roa'] += 1
                    stats['num_roa'] += 1
        
        # Update max_branch (maximum CA branching factor)
        stats['max_branch'] = max(stats['max_branch'], child_ca_count)
        
        # Record structure
        stats['structure'].append({
            'name': ca_name,
            'depth': depth,
            'is_leaf': child_ca_count == 0,
            'files': file_counts,
            'child_ca_count': child_ca_count
        })
        
        if child_ca_count == 0:
            stats['leaf_count'] += 1
        
        return child_ca_count == 0
    
    def _has_ca_cert(self, dir_path: str) -> bool:
        """Check if directory contains a CA certificate."""
        try:
            for filename in os.listdir(dir_path):
                if filename.endswith('.cer'):
                    return True
        except PermissionError:
            pass
        return False
    
    def print_structure(self, stats: Dict) -> None:
        """Print the repository structure."""
        print("RPKI Repository Structure")
        print("=" * 50)
        
        for item in stats['structure']:
            indent = "  " * item['depth']
            leaf_marker = " (leaf)" if item['is_leaf'] else ""
            files = item['files']
            file_summary = []
            if files['mft'] > 0:
                file_summary.append(f"{files['mft']} MFT")
            if files['crl'] > 0:
                file_summary.append(f"{files['crl']} CRL")
            if files['roa'] > 0:
                file_summary.append(f"{files['roa']} ROA")
            if files['cert'] > 0:
                file_summary.append(f"{files['cert']} cert(s)")
            
            file_str = f" [{', '.join(file_summary)}]" if file_summary else ""
            print(f"{indent}{item['name']}{leaf_marker}{file_str}")


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="RPKI Repository Visualization Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python visualize_repo.py /path/to/repo
  python visualize_repo.py /path/to/repo --mode stats
  python visualize_repo.py /path/to/repo --max-depth 5 --max-files 20
        """
    )
    parser.add_argument("repo", help="Path to the RPKI repository directory")
    parser.add_argument("--mode", choices=['tree', 'compact', 'detailed', 'stats'],
                        default='tree', help="Visualization mode")
    parser.add_argument("--ascii", action="store_true",
                        help="Use ASCII characters instead of Unicode")
    parser.add_argument("--no-icons", action="store_true",
                        help="Don't use icons in output")
    parser.add_argument("--direct", action="store_true",
                        help="Use direct directory scanning (faster for large repos)")
    parser.add_argument("--max-depth", type=int, default=3,
                        help="Maximum depth to display (default: 3)")
    parser.add_argument("--max-files", type=int, default=10,
                        help="Maximum files to display per CA (default: 10)")
    
    args = parser.parse_args()
    
    # Validate repository path
    if not os.path.isdir(args.repo):
        print(f"Error: Repository directory not found: {args.repo}")
        sys.exit(1)
    
    try:
        if args.direct or args.mode == 'stats':
            # Use direct scanning
            scanner = DirectRepoScanner(args.repo)
            stats = scanner.scan()
            
            if args.mode == 'stats':
                # Print stats using the scanner's data
                print("RPKI Repository Statistics")
                print("=" * 50)
                
                # Structure metrics
                print("\n[Structure Metrics]")
                print(f"  depth:      {stats['depth']}")
                print(f"  num_ca:     {stats['num_ca']}")
                print(f"  num_cert:   {stats['num_cert']}")
                print(f"  max_branch: {stats['max_branch']}")
                print(f"  leaf_count: {stats['leaf_count']}")
                
                # Quantity metrics
                print("\n[Quantity Metrics]")
                print(f"  num_roa:    {stats['num_roa']}")
                print(f"  num_mft:    {stats['num_mft']}")
                print(f"  num_crl:    {stats['num_crl']}")
                print()
                
                # CAs by depth
                print("CAs by Depth:")
                for depth in sorted(stats['ca_by_depth'].keys()):
                    print(f"  Depth {depth}: {stats['ca_by_depth'][depth]} CA(s)")
            else:
                scanner.print_structure(stats)
        else:
            # Build tree and print
            builder = RepoTreeBuilder(args.repo)
            root = builder.build()
            
            printer = RepoTreePrinter(
                use_unicode=not args.ascii,
                use_icons=not args.no_icons
            )
            
            if args.mode == 'tree':
                printer.print_tree(root, max_depth=args.max_depth, max_files=args.max_files)
            elif args.mode == 'compact':
                printer.print_compact(root)
            elif args.mode == 'detailed':
                printer.print_detailed(root)
            
            # Print stats at the end
            print()
            collector = RepoStatsCollector(root)
            collector.collect()
            collector.print_stats()
    
    except Exception as e:
        import traceback
        print(f"Error: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
