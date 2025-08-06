#!/usr/bin/env python3
"""
BSP Texture/Shader Extractor GUI for ioquake3-based games
Clean version with shader file parsing support.
"""

import struct
import os
import re
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from typing import List, Dict, Tuple, Set
import threading
from pathlib import Path

class AssetExtractor:
    def __init__(self):
        self.texture_extensions = ['.tga', '.jpg', '.jpeg', '.png']
        self.found_textures = {}
        self.found_shaders = {}
        self.shader_definitions = {}
        self.parsed_files = []
    
    def find_scripts_folder(self, bsp_path):
        """Find the scripts folder relative to the BSP file"""
        if not bsp_path:
            return ""
            
        bsp_dir = Path(bsp_path).parent
        
        # Common locations to check
        search_paths = [
            bsp_dir / "scripts",
            bsp_dir / ".." / "scripts", 
            bsp_dir / ".." / ".." / "scripts",
            bsp_dir / "baseq3" / "scripts",
            bsp_dir / ".." / "baseq3" / "scripts"
        ]
        
        for path in search_paths:
            if path.exists() and path.is_dir():
                return str(path)
        
        return ""
    
    def parse_shader_file(self, filepath):
        """Parse a single .shader file and extract shader definitions"""
        shaders = {}
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            return shaders
        
        # Remove C-style comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        
        # Find shader blocks using regex
        shader_pattern = r'(\S+)\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
        matches = re.findall(shader_pattern, content, re.MULTILINE | re.DOTALL)
        
        for shader_name, shader_body in matches:
            shader_name = shader_name.strip()
            if not shader_name:
                continue
                
            shader_info = {
                'name': shader_name,
                'file': os.path.basename(filepath),
                'properties': {},
                'stages': []
            }
            
            # Parse shader properties
            lines = shader_body.split('\n')
            current_stage = None
            brace_level = 0
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                # Count braces for stage detection
                brace_level += line.count('{') - line.count('}')
                
                if line == '{':
                    if current_stage is not None:
                        continue
                    current_stage = {}
                elif line == '}' and current_stage is not None:
                    shader_info['stages'].append(current_stage)
                    current_stage = None
                elif current_stage is not None:
                    # Inside a stage block
                    if ' ' in line:
                        key, value = line.split(' ', 1)
                        current_stage[key] = value
                else:
                    # Main shader properties
                    if ' ' in line:
                        parts = line.split(' ', 1)
                        key = parts[0]
                        value = parts[1] if len(parts) > 1 else ''
                        shader_info['properties'][key] = value
            
            shaders[shader_name] = shader_info
            
        return shaders
    
    def parse_scripts_folder(self, scripts_path):
        """Parse all .shader files in the scripts folder"""
        if not scripts_path or not os.path.exists(scripts_path):
            return {}, []
        
        all_shaders = {}
        parsed_files = []
        
        try:
            for filename in os.listdir(scripts_path):
                if filename.lower().endswith('.shader'):
                    filepath = os.path.join(scripts_path, filename)
                    file_shaders = self.parse_shader_file(filepath)
                    all_shaders.update(file_shaders)
                    parsed_files.append(filename)
        except Exception as e:
            print(f"Error parsing scripts folder: {e}")
        
        self.shader_definitions = all_shaders
        self.parsed_files = parsed_files
        
        return all_shaders, parsed_files
        
    def find_texture_files(self, texture_names: Set[str], search_paths: List[str]) -> Dict[str, str]:
        """Find actual texture files for the given texture names"""
        found_files = {}
        
        for texture_name in texture_names:
            # Try different variations of the texture path
            texture_variants = [
                texture_name,
                f"textures/{texture_name}",
                texture_name.replace('textures/', ''),
            ]
            
            for variant in texture_variants:
                for search_path in search_paths:
                    for ext in self.texture_extensions:
                        # Try with and without extension
                        test_paths = [
                            os.path.join(search_path, f"{variant}{ext}"),
                            os.path.join(search_path, f"{variant}.{ext.lstrip('.')}"),
                        ]
                        
                        for test_path in test_paths:
                            if os.path.exists(test_path):
                                found_files[texture_name] = test_path
                                break
                    if texture_name in found_files:
                        break
                if texture_name in found_files:
                    break
        
        return found_files
    
    def find_shader_files(self, shader_definitions: Dict[str, Dict], scripts_paths: List[str]) -> Dict[str, str]:
        """Find shader files that contain the used shader definitions"""
        used_files = {}
        
        # Get unique shader files from definitions
        shader_files = set()
        for shader_def in shader_definitions.values():
            shader_files.add(shader_def['file'])
        
        # Find full paths to these files
        for shader_file in shader_files:
            for scripts_path in scripts_paths:
                full_path = os.path.join(scripts_path, shader_file)
                if os.path.exists(full_path):
                    used_files[shader_file] = full_path
                    break
        
        return used_files
    
    def create_asset_package(self, output_dir: str, textures: Dict[str, str], 
                           shaders: Dict[str, str], bsp_files: List[str],
                           callback=None) -> Tuple[bool, str]:
        """Create directory structure with all required assets"""
        try:
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            
            # Create subdirectories
            textures_dir = os.path.join(output_dir, "textures")
            scripts_dir = os.path.join(output_dir, "scripts")
            maps_dir = os.path.join(output_dir, "maps")
            
            os.makedirs(textures_dir, exist_ok=True)
            os.makedirs(scripts_dir, exist_ok=True)
            os.makedirs(maps_dir, exist_ok=True)
            
            total_files = len(textures) + len(shaders) + len(bsp_files)
            copied_files = 0
            
            # Copy texture files
            if callback:
                callback(f"Copying {len(textures)} texture files...")
            
            for texture_name, source_path in textures.items():
                # Determine target path, preserving directory structure
                if texture_name.startswith('textures/'):
                    rel_path = texture_name[9:]  # Remove 'textures/' prefix
                else:
                    rel_path = texture_name
                
                target_path = os.path.join(textures_dir, rel_path)
                target_dir = os.path.dirname(target_path)
                os.makedirs(target_dir, exist_ok=True)
                
                # Add appropriate extension if missing
                if not any(target_path.lower().endswith(ext) for ext in self.texture_extensions):
                    source_ext = os.path.splitext(source_path)[1]
                    target_path += source_ext
                
                shutil.copy2(source_path, target_path)
                copied_files += 1
                
                if callback:
                    callback(f"Copied texture: {os.path.basename(target_path)} ({copied_files}/{total_files})")
            
            # Copy shader files
            if callback:
                callback(f"Copying {len(shaders)} shader files...")
            
            for shader_file, source_path in shaders.items():
                target_path = os.path.join(scripts_dir, shader_file)
                shutil.copy2(source_path, target_path)
                copied_files += 1
                
                if callback:
                    callback(f"Copied shader: {shader_file} ({copied_files}/{total_files})")
            
            # Copy BSP files
            if callback:
                callback(f"Copying {len(bsp_files)} BSP files...")
            
            for bsp_file in bsp_files:
                filename = os.path.basename(bsp_file)
                target_path = os.path.join(maps_dir, filename)
                shutil.copy2(bsp_file, target_path)
                copied_files += 1
                
                if callback:
                    callback(f"Copied map: {filename} ({copied_files}/{total_files})")
            
            # Create summary file
            summary_path = os.path.join(output_dir, "asset_summary.txt")
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write("Asset Package Summary\n")
                f.write("=" * 30 + "\n\n")
                f.write(f"Created: {Path(output_dir).name}\n")
                f.write(f"Source BSP files: {len(bsp_files)}\n")
                f.write(f"Texture files: {len(textures)}\n")
                f.write(f"Shader files: {len(shaders)}\n")
                f.write(f"Total files: {total_files}\n\n")
                
                f.write("BSP Files:\n")
                for bsp_file in bsp_files:
                    f.write(f"  - {os.path.basename(bsp_file)}\n")
                
                f.write(f"\nShader Files:\n")
                for shader_file in sorted(shaders.keys()):
                    f.write(f"  - {shader_file}\n")
                
                f.write(f"\nTexture Files:\n")
                for texture_name in sorted(textures.keys()):
                    f.write(f"  - {texture_name}\n")
            
            return True, f"Successfully created asset package with {total_files} files"
            
        except Exception as e:
            return False, f"Error creating asset package: {str(e)}"

class BSPReader:
    def __init__(self):
        self.filepath = ""
        self.file_data = None
        self.header = None
        self.lumps = {}
        
    def read_file(self, filepath):
        """Read the BSP file into memory"""
        self.filepath = filepath
        try:
            with open(filepath, 'rb') as f:
                self.file_data = f.read()
            return True, f"Successfully read {len(self.file_data)} bytes"
        except FileNotFoundError:
            return False, f"File {filepath} not found!"
        except Exception as e:
            return False, f"Error reading file: {e}"
    
    def parse_header(self):
        """Parse BSP header and lump directory"""
        if not self.file_data or len(self.file_data) < 8:
            return False, "File too small to be a valid BSP"
            
        # Read magic number and version
        magic = self.file_data[:4]
        version = struct.unpack('<I', self.file_data[4:8])[0]
        
        # Check if it's a valid Quake 3 BSP
        if magic != b'IBSP':
            return False, "Not a valid Quake 3 BSP file (wrong magic number)"
            
        if version != 46:
            return False, f"Unusual BSP version {version} (expected 46)"
        
        # Read lump directory (17 lumps, each 8 bytes)
        self.lumps = {}
        lump_offset = 8
        for i in range(17):
            offset, length = struct.unpack('<II', self.file_data[lump_offset:lump_offset+8])
            self.lumps[i] = {'offset': offset, 'length': length}
            lump_offset += 8
            
        return True, f"Parsed {len(self.lumps)} lumps successfully"
    
    def extract_textures(self):
        """Extract texture/shader names from lump 1 (textures)"""
        if 1 not in self.lumps:
            return [], "Texture lump not found"
            
        lump = self.lumps[1]
        if lump['length'] == 0:
            return [], "Texture lump is empty"
        
        textures = []
        offset = lump['offset']
        end_offset = offset + lump['length']
        
        # Each texture entry is 72 bytes (64 byte name + 8 bytes flags/contents)
        texture_size = 72
        num_textures = lump['length'] // texture_size
        
        for i in range(num_textures):
            if offset + texture_size > end_offset:
                break
                
            # Read 64-byte null-terminated string for texture name
            name_data = self.file_data[offset:offset+64]
            null_pos = name_data.find(b'\x00')
            if null_pos != -1:
                name_data = name_data[:null_pos]
                
            try:
                texture_name = name_data.decode('ascii', errors='ignore')
                if texture_name:  # Only add non-empty names
                    textures.append(texture_name)
            except UnicodeDecodeError:
                pass  # Skip invalid entries
                
            offset += texture_size
            
        return textures, f"Found {len(textures)} texture entries"
    
    def get_lump_info(self):
        """Get information about all lumps"""
        lump_names = {
            0: "Entities", 1: "Textures", 2: "Planes", 3: "Nodes", 4: "Leafs",
            5: "Leaffaces", 6: "Leafbrushes", 7: "Models", 8: "Brushes",
            9: "Brushsides", 10: "Vertexes", 11: "Meshverts", 12: "Effects",
            13: "Faces", 14: "Lightmaps", 15: "Lightvols", 16: "Visdata"
        }
        
        lump_info = {}
        for i, lump in self.lumps.items():
            name = lump_names.get(i, f"Unknown_{i}")
            lump_info[i] = {
                'name': name,
                'offset': lump['offset'],
                'length': lump['length']
            }
        return lump_info

class BSPAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BSP Texture/Shader Analyzer")
        self.root.geometry("1000x700")
        
        self.bsp_reader = BSPReader()
        self.asset_extractor = AssetExtractor()  # Jetzt nur noch ein Objekt
        self.current_textures = []
        self.shader_definitions = {}
        self.scripts_folder = ""
        self.texture_search_paths = []
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="5")
        file_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        self.file_var = tk.StringVar()
        ttk.Label(file_frame, text="BSP File:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        ttk.Entry(file_frame, textvariable=self.file_var, state="readonly").grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(file_frame, text="Browse...", command=self.browse_file).grid(row=0, column=2)
        ttk.Button(file_frame, text="Analyze", command=self.analyze_file).grid(row=0, column=3, padx=(5, 0))
        
        # Scripts folder selection
        self.scripts_var = tk.StringVar()
        ttk.Label(file_frame, text="Scripts:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        ttk.Entry(file_frame, textvariable=self.scripts_var, state="readonly").grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(5, 0))
        ttk.Button(file_frame, text="Browse...", command=self.browse_scripts).grid(row=1, column=2, pady=(5, 0))
        ttk.Button(file_frame, text="Auto-Find", command=self.auto_find_scripts).grid(row=1, column=3, padx=(5, 0), pady=(5, 0))
        
        # Progress bar
        self.progress = ttk.Progressbar(file_frame, mode='indeterminate')
        self.progress.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready - Select a BSP file to analyze")
        ttk.Label(main_frame, textvariable=self.status_var).grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))
        
        # Results notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Asset Extractor tab
        extractor_frame = ttk.Frame(self.notebook)
        self.notebook.add(extractor_frame, text="Asset Extractor")
        
        # Multi-file selection
        multi_frame = ttk.LabelFrame(extractor_frame, text="Batch Asset Extraction", padding="10")
        multi_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(multi_frame, text="Select multiple BSP files to extract all their assets:").pack(anchor=tk.W, pady=(0, 5))
        
        self.bsp_files_var = tk.StringVar()
        files_frame = ttk.Frame(multi_frame)
        files_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Entry(files_frame, textvariable=self.bsp_files_var, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(files_frame, text="Select BSP Files...", command=self.select_multiple_bsp).pack(side=tk.RIGHT)
        
        # Texture search paths
        ttk.Label(multi_frame, text="Texture search paths (one per line):").pack(anchor=tk.W, pady=(10, 5))
        self.texture_paths_text = tk.Text(multi_frame, height=4, wrap=tk.WORD)
        self.texture_paths_text.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(multi_frame, text="Add Texture Folder...", command=self.add_texture_path).pack(anchor=tk.W, pady=(0, 5))
        
        # Output settings
        output_frame = ttk.Frame(multi_frame)
        output_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.output_dir_var = tk.StringVar()
        ttk.Label(output_frame, text="Output folder:").pack(anchor=tk.W)
        dir_frame = ttk.Frame(output_frame)
        dir_frame.pack(fill=tk.X, pady=(5, 10))
        
        ttk.Entry(dir_frame, textvariable=self.output_dir_var, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(dir_frame, text="Browse...", command=self.select_output_dir).pack(side=tk.RIGHT)
        
        # Extract button
        ttk.Button(multi_frame, text="Extract Assets", command=self.extract_assets).pack(pady=(0, 5))
        
        # Extraction progress
        self.extraction_progress = ttk.Progressbar(multi_frame, mode='determinate')
        self.extraction_progress.pack(fill=tk.X, pady=(0, 5))
        
        self.extraction_status_var = tk.StringVar(value="Ready to extract assets")
        ttk.Label(multi_frame, textvariable=self.extraction_status_var).pack(anchor=tk.W)
        
        # Textures tab
        textures_frame = ttk.Frame(self.notebook)
        self.notebook.add(textures_frame, text="Textures")
        
        # Textures list with scrollbar
        tex_list_frame = ttk.Frame(textures_frame)
        tex_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.textures_listbox = tk.Listbox(tex_list_frame, selectmode=tk.EXTENDED)
        tex_scrollbar = ttk.Scrollbar(tex_list_frame, orient=tk.VERTICAL, command=self.textures_listbox.yview)
        self.textures_listbox.configure(yscrollcommand=tex_scrollbar.set)
        
        self.textures_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tex_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Textures buttons
        tex_btn_frame = ttk.Frame(textures_frame)
        tex_btn_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(tex_btn_frame, text="Copy Selected", command=self.copy_selected_textures).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(tex_btn_frame, text="Export All", command=self.export_textures).pack(side=tk.LEFT, padx=(0, 5))
        self.tex_count_var = tk.StringVar()
        ttk.Label(tex_btn_frame, textvariable=self.tex_count_var).pack(side=tk.RIGHT)
        
        # Shaders tab
        shaders_frame = ttk.Frame(self.notebook)
        self.notebook.add(shaders_frame, text="Shaders")
        
        # Shaders treeview
        shader_tree_frame = ttk.Frame(shaders_frame)
        shader_tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.shaders_tree = ttk.Treeview(shader_tree_frame, columns=('file', 'properties', 'stages'), show='tree headings')
        self.shaders_tree.heading('#0', text='Shader Name')
        self.shaders_tree.heading('file', text='Shader File')
        self.shaders_tree.heading('properties', text='Properties')
        self.shaders_tree.heading('stages', text='Stages')
        
        self.shaders_tree.column('#0', width=300)
        self.shaders_tree.column('file', width=150)
        self.shaders_tree.column('properties', width=200)
        self.shaders_tree.column('stages', width=100)
        
        shader_scrollbar = ttk.Scrollbar(shader_tree_frame, orient=tk.VERTICAL, command=self.shaders_tree.yview)
        self.shaders_tree.configure(yscrollcommand=shader_scrollbar.set)
        
        self.shaders_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        shader_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Shader buttons
        shader_btn_frame = ttk.Frame(shaders_frame)
        shader_btn_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(shader_btn_frame, text="Copy Selected", command=self.copy_selected_shaders).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(shader_btn_frame, text="Export All", command=self.export_shaders).pack(side=tk.LEFT, padx=(0, 5))
        self.shader_count_var = tk.StringVar()
        ttk.Label(shader_btn_frame, textvariable=self.shader_count_var).pack(side=tk.RIGHT)
        
        # Lump Info tab
        lump_frame = ttk.Frame(self.notebook)
        self.notebook.add(lump_frame, text="Lump Info")
        
        # Lump info treeview
        lump_tree_frame = ttk.Frame(lump_frame)
        lump_tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.lump_tree = ttk.Treeview(lump_tree_frame, columns=('offset', 'length'), show='tree headings')
        self.lump_tree.heading('#0', text='Lump Name')
        self.lump_tree.heading('offset', text='Offset')
        self.lump_tree.heading('length', text='Length')
        
        lump_scrollbar2 = ttk.Scrollbar(lump_tree_frame, orient=tk.VERTICAL, command=self.lump_tree.yview)
        self.lump_tree.configure(yscrollcommand=lump_scrollbar2.set)
        
        self.lump_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lump_scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Log")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def browse_file(self):
        """Open file dialog to select BSP file"""
        filename = filedialog.askopenfilename(
            title="Select BSP file",
            filetypes=[("BSP files", "*.bsp"), ("All files", "*.*")]
        )
        if filename:
            self.file_var.set(filename)
            
    def browse_scripts(self):
        """Open directory dialog to select scripts folder"""
        folder = filedialog.askdirectory(
            title="Select scripts folder"
        )
        if folder:
            self.scripts_var.set(folder)
            self.scripts_folder = folder
            
    def auto_find_scripts(self):
        """Automatically find scripts folder relative to BSP file"""
        bsp_file = self.file_var.get()
        if not bsp_file:
            messagebox.showwarning("No BSP File", "Please select a BSP file first!")
            return
            
        scripts_path = self.asset_extractor.find_scripts_folder(bsp_file)
        if scripts_path:
            self.scripts_var.set(scripts_path)
            self.scripts_folder = scripts_path
            messagebox.showinfo("Found Scripts", f"Found scripts folder: {scripts_path}")
        else:
            messagebox.showwarning("Not Found", "Could not find scripts folder automatically.\nPlease select it manually.")
    
    def select_multiple_bsp(self):
        """Select multiple BSP files for batch processing"""
        filenames = filedialog.askopenfilenames(
            title="Select BSP files",
            filetypes=[("BSP files", "*.bsp"), ("All files", "*.*")]
        )
        if filenames:
            self.bsp_files_var.set(f"{len(filenames)} files selected")
            self.selected_bsp_files = filenames
            
    def add_texture_path(self):
        """Add a texture search path"""
        folder = filedialog.askdirectory(title="Select texture folder")
        if folder:
            current_text = self.texture_paths_text.get("1.0", tk.END).strip()
            if current_text:
                current_text += "\n"
            current_text += folder
            self.texture_paths_text.delete("1.0", tk.END)
            self.texture_paths_text.insert("1.0", current_text)
            
    def select_output_dir(self):
        """Select output directory for asset extraction"""
        folder = filedialog.askdirectory(title="Select output folder")
        if folder:
            self.output_dir_var.set(folder)
            
    def extract_assets(self):
        """Extract assets from multiple BSP files"""
        if not hasattr(self, 'selected_bsp_files') or not self.selected_bsp_files:
            messagebox.showerror("Error", "Please select BSP files first!")
            return
            
        if not self.output_dir_var.get():
            messagebox.showerror("Error", "Please select an output folder!")
            return
            
        # Get texture search paths
        texture_paths_text = self.texture_paths_text.get("1.0", tk.END).strip()
        texture_paths = [path.strip() for path in texture_paths_text.split('\n') if path.strip()]
        
        if not texture_paths:
            result = messagebox.askyesno("No Texture Paths", 
                                       "No texture search paths specified. Continue anyway?\n"
                                       "(Only shader files will be extracted)")
            if not result:
                return
        
        # Start extraction in separate thread
        self.extraction_progress['value'] = 0
        self.extraction_status_var.set("Starting asset extraction...")
        
        thread = threading.Thread(target=self._extract_worker, 
                                args=(self.selected_bsp_files, texture_paths, self.output_dir_var.get()))
        thread.daemon = True
        thread.start()
        
    def _extract_worker(self, bsp_files, texture_paths, output_dir):
        """Worker function for asset extraction"""
        try:
            all_textures = set()
            all_shader_definitions = {}
            
            # Analyze all BSP files
            total_bsp = len(bsp_files)
            for i, bsp_file in enumerate(bsp_files):
                self.root.after(0, lambda i=i, total=total_bsp, name=os.path.basename(bsp_file): 
                              self.extraction_status_var.set(f"Analyzing {name} ({i+1}/{total})..."))
                
                # Read and parse BSP
                reader = BSPReader()
                success, message = reader.read_file(bsp_file)
                if not success:
                    continue
                    
                success, message = reader.parse_header()
                if not success:
                    continue
                    
                textures, tex_message = reader.extract_textures()
                all_textures.update(textures)
                
                # Update progress
                progress = int((i + 1) / total_bsp * 30)  # First 30% for BSP analysis
                self.root.after(0, lambda p=progress: setattr(self.extraction_progress, 'value', p))
            
            # Parse shader files if scripts folder is set
            if self.scripts_folder:
                self.root.after(0, lambda: self.extraction_status_var.set("Parsing shader files..."))
                shader_defs, parsed_files = self.asset_extractor.parse_scripts_folder(self.scripts_folder)
                all_shader_definitions.update(shader_defs)
                
                progress = 40
                self.root.after(0, lambda p=progress: setattr(self.extraction_progress, 'value', p))
            
            # Find texture files
            self.root.after(0, lambda: self.extraction_status_var.set("Finding texture files..."))
            found_textures = self.asset_extractor.find_texture_files(all_textures, texture_paths)
            
            progress = 60
            self.root.after(0, lambda p=progress: setattr(self.extraction_progress, 'value', p))
            
            # Find shader files
            self.root.after(0, lambda: self.extraction_status_var.set("Finding shader files..."))
            scripts_paths = [self.scripts_folder] if self.scripts_folder else []
            found_shaders = self.asset_extractor.find_shader_files(all_shader_definitions, scripts_paths)
            
            progress = 70
            self.root.after(0, lambda p=progress: setattr(self.extraction_progress, 'value', p))
            
            # Create asset package
            def progress_callback(message):
                self.root.after(0, lambda m=message: self.extraction_status_var.set(m))
            
            success, message = self.asset_extractor.create_asset_package(
                output_dir, found_textures, found_shaders, bsp_files, progress_callback
            )
            
            progress = 100
            self.root.after(0, lambda p=progress: setattr(self.extraction_progress, 'value', p))
            
            # Show results
            if success:
                result_msg = (f"Asset extraction completed!\n\n"
                            f"Processed: {len(bsp_files)} BSP files\n"
                            f"Found: {len(found_textures)} texture files\n"
                            f"Found: {len(found_shaders)} shader files\n"
                            f"Missing: {len(all_textures) - len(found_textures)} textures\n\n"
                            f"Assets saved to: {output_dir}")
                
                self.root.after(0, lambda msg=result_msg: self.extraction_status_var.set("Extraction completed!"))
                self.root.after(0, lambda msg=result_msg: messagebox.showinfo("Extraction Complete", msg))
            else:
                self.root.after(0, lambda msg=message: self.extraction_status_var.set(f"Error: {msg}"))
                self.root.after(0, lambda msg=message: messagebox.showerror("Extraction Error", msg))
                
        except Exception as e:
            error_msg = f"Error during extraction: {str(e)}"
            self.root.after(0, lambda msg=error_msg: self.extraction_status_var.set(msg))
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Extraction Error", msg))
            
    def log_message(self, message):
        """Add message to log tab"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def analyze_file(self):
        """Analyze the selected BSP file in a separate thread"""
        filepath = self.file_var.get()
        if not filepath:
            messagebox.showerror("Error", "Please select a BSP file first!")
            return
            
        if not os.path.exists(filepath):
            messagebox.showerror("Error", f"File does not exist: {filepath}")
            return
        
        # Start analysis in separate thread to prevent GUI freezing
        self.progress.start()
        self.status_var.set("Analyzing BSP file...")
        
        thread = threading.Thread(target=self._analyze_worker, args=(filepath,))
        thread.daemon = True
        thread.start()
        
    def _analyze_worker(self, filepath):
        """Worker function for BSP analysis"""
        try:
            self.log_message(f"Starting analysis of: {os.path.basename(filepath)}")
            
            # Read file
            success, message = self.bsp_reader.read_file(filepath)
            self.log_message(message)
            if not success:
                self.root.after(0, lambda: self._analysis_complete(False, message))
                return
            
            # Parse header
            success, message = self.bsp_reader.parse_header()
            self.log_message(message)
            if not success:
                self.root.after(0, lambda: self._analysis_complete(False, message))
                return
            
            # Extract textures
            self.current_textures, tex_message = self.bsp_reader.extract_textures()
            self.log_message(tex_message)
            
            # Parse shader files if scripts folder is set
            if self.scripts_folder:
                self.log_message(f"Parsing shader files in: {self.scripts_folder}")
                self.shader_definitions, parsed_files = self.asset_extractor.parse_scripts_folder(self.scripts_folder)
                self.log_message(f"Parsed {len(parsed_files)} shader files, found {len(self.shader_definitions)} shader definitions")
            else:
                self.log_message("No scripts folder specified - shader definitions not loaded")
            
            # Update GUI in main thread
            self.root.after(0, lambda: self._analysis_complete(True, "Analysis completed successfully!"))
            
        except Exception as e:
            error_msg = f"Error during analysis: {str(e)}"
            self.log_message(error_msg)
            self.root.after(0, lambda: self._analysis_complete(False, error_msg))
            
    def _analysis_complete(self, success, message):
        """Called when analysis is complete"""
        self.progress.stop()
        
        if success:
            self.status_var.set(message)
            self._populate_results()
        else:
            self.status_var.set(f"Error: {message}")
            messagebox.showerror("Analysis Error", message)
            
    def _populate_results(self):
        """Populate the results tabs with extracted data"""
        # Clear existing data
        self.textures_listbox.delete(0, tk.END)
        self.shaders_tree.delete(*self.shaders_tree.get_children())
        self.lump_tree.delete(*self.lump_tree.get_children())
        
        # Populate textures
        unique_textures = sorted(set(self.current_textures))
        for texture in unique_textures:
            self.textures_listbox.insert(tk.END, texture)
        self.tex_count_var.set(f"Total: {len(unique_textures)}")
        
        # Populate shaders with actual shader definitions
        used_textures = set(self.current_textures)
        found_shaders = 0
        missing_shaders = []
        
        for texture_name in sorted(used_textures):
            if texture_name in self.shader_definitions:
                shader_def = self.shader_definitions[texture_name]
                properties_list = list(shader_def['properties'].items())[:3]
                properties_text = ', '.join([f"{k}: {v}" for k, v in properties_list])
                if len(shader_def['properties']) > 3:
                    properties_text += "..."
                    
                self.shaders_tree.insert('', 'end', text=texture_name,
                                       values=(shader_def['file'], 
                                              properties_text,
                                              len(shader_def['stages'])))
                found_shaders += 1
            else:
                # Texture without shader definition
                self.shaders_tree.insert('', 'end', text=texture_name,
                                       values=("(no shader file)", "texture only", "0"))
                missing_shaders.append(texture_name)
        
        shader_status = f"Found: {found_shaders}, Missing: {len(missing_shaders)}"
        self.shader_count_var.set(f"Total: {len(used_textures)} ({shader_status})")
        
        # Populate lump info
        lump_info = self.bsp_reader.get_lump_info()
        for lump_id, info in lump_info.items():
            self.lump_tree.insert('', 'end', text=f"{lump_id:2d} - {info['name']}",
                                values=(f"{info['offset']:8d}", f"{info['length']:8d}"))
        
        self.log_message("Results populated successfully!")
        
    def copy_selected_textures(self):
        """Copy selected textures to clipboard"""
        selection = self.textures_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select textures to copy!")
            return
            
        selected_textures = [self.textures_listbox.get(i) for i in selection]
        clipboard_text = '\n'.join(selected_textures)
        
        self.root.clipboard_clear()
        self.root.clipboard_append(clipboard_text)
        messagebox.showinfo("Copied", f"Copied {len(selected_textures)} textures to clipboard!")
        
    def copy_selected_shaders(self):
        """Copy selected shaders to clipboard"""
        selection = self.shaders_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select shaders to copy!")
            return
            
        selected_shaders = []
        for item in selection:
            shader_name = self.shaders_tree.item(item)['text']
            if shader_name in self.shader_definitions:
                # Copy full shader definition
                shader_def = self.shader_definitions[shader_name]
                shader_text = f"{shader_name}\n{{\n"
                
                # Add properties
                for key, value in shader_def['properties'].items():
                    shader_text += f"    {key} {value}\n"
                
                # Add stages
                for stage in shader_def['stages']:
                    shader_text += "    {\n"
                    for key, value in stage.items():
                        shader_text += f"        {key} {value}\n"
                    shader_text += "    }\n"
                
                shader_text += "}\n\n"
                selected_shaders.append(shader_text)
            else:
                selected_shaders.append(shader_name)
        
        clipboard_text = '\n'.join(selected_shaders)
        
        self.root.clipboard_clear()
        self.root.clipboard_append(clipboard_text)
        messagebox.showinfo("Copied", f"Copied {len(selected_shaders)} shader definitions to clipboard!")
        
    def export_textures(self):
        """Export all textures to a text file"""
        if not self.current_textures:
            messagebox.showwarning("No Data", "No textures to export!")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save textures as...",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                unique_textures = sorted(set(self.current_textures))
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Textures from: {os.path.basename(self.bsp_reader.filepath)}\n")
                    f.write("=" * 50 + "\n\n")
                    for texture in unique_textures:
                        f.write(f"{texture}\n")
                        
                messagebox.showinfo("Export Complete", f"Exported {len(unique_textures)} textures to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Could not save file: {e}")
                
    def export_shaders(self):
        """Export all shaders with their definitions to a text file"""
        if not self.current_textures:
            messagebox.showwarning("No Data", "No textures/shaders to export!")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save shaders as...",
            defaultextension=".shader",
            filetypes=[("Shader files", "*.shader"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"// Shaders extracted from: {os.path.basename(self.bsp_reader.filepath)}\n")
                    f.write(f"// Scripts folder: {self.scripts_folder}\n")
                    f.write("// " + "=" * 50 + "\n\n")
                    
                    used_textures = sorted(set(self.current_textures))
                    found_count = 0
                    
                    for texture_name in used_textures:
                        if texture_name in self.shader_definitions:
                            shader_def = self.shader_definitions[texture_name]
                            f.write(f"{texture_name}\n{{\n")
                            
                            # Write properties
                            for key, value in shader_def['properties'].items():
                                f.write(f"    {key} {value}\n")
                            
                            # Write stages
                            for stage in shader_def['stages']:
                                f.write("    {\n")
                                for key, value in stage.items():
                                    f.write(f"        {key} {value}\n")
                                f.write("    }\n")
                            
                            f.write("}\n\n")
                            found_count += 1
                        else:
                            f.write(f"// {texture_name} - NO SHADER DEFINITION FOUND\n\n")
                        
                messagebox.showinfo("Export Complete", 
                                  f"Exported {len(used_textures)} textures to {filename}\n"
                                  f"({found_count} with shader definitions, {len(used_textures)-found_count} without)")
            except Exception as e:
                messagebox.showerror("Export Error", f"Could not save file: {e}")

def main():
    root = tk.Tk()
    app = BSPAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()