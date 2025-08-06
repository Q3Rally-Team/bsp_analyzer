# BSP Texture/Shader Analyzer

A comprehensive GUI tool for analyzing and extracting assets from Quake 3 engine BSP files (ioquake3-based games). This tool helps developers, modders, and map makers extract textures, shaders, and other assets from BSP map files.

![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## Features

### 🎯 Core Functionality
- **BSP File Analysis**: Parse Quake 3 BSP files and extract texture/shader references
- **Shader Parsing**: Read and analyze .shader files with full definition support
- **Asset Extraction**: Batch process multiple BSP files and extract all required assets
- **Smart Asset Discovery**: Automatically find textures and shaders in common directory structures

### 📊 Analysis Tools
- **Texture Browser**: View all textures referenced in BSP files
- **Shader Inspector**: Browse shader definitions with properties and stages
- **Lump Information**: Detailed BSP file structure analysis
- **Missing Asset Detection**: Identify textures without corresponding shader definitions

### 🔧 Export & Extraction
- **Batch Asset Extraction**: Process multiple maps at once
- **Organized Output**: Creates proper directory structure (textures/, scripts/, maps/)
- **Asset Summary**: Generates detailed reports of extracted assets
- **Clipboard Integration**: Copy texture/shader lists for external use
- **File Export**: Save texture lists and shader definitions

### 🎨 User Interface
- **Tabbed Interface**: Organized workflow with dedicated tabs for different functions
- **Progress Tracking**: Real-time progress bars for long operations
- **Comprehensive Logging**: Detailed operation logs for debugging
- **Auto-Discovery**: Automatically locate scripts folders relative to BSP files

## Installation

### Prerequisites
- Python 3.7 or higher
- tkinter (usually included with Python)

### Clone and Run
```bash
git clone https://github.com/yourusername/bsp-analyzer.git
cd bsp-analyzer
python bsp_analyzer.py
```

### Dependencies
The tool uses only Python standard library modules:
- `tkinter` - GUI framework
- `struct` - Binary data parsing
- `os`, `shutil`, `pathlib` - File operations
- `re` - Regular expressions for shader parsing
- `threading` - Background processing

## Usage

### Quick Start
1. Launch the application: `python bsp_analyzer.py`
2. Click "Browse..." to select a BSP file
3. Click "Auto-Find" to locate the scripts folder (or browse manually)
4. Click "Analyze" to parse the BSP file

### Asset Extraction Workflow
1. Switch to the "Asset Extractor" tab
2. Click "Select BSP Files..." to choose multiple BSP files
3. Add texture search paths using "Add Texture Folder..."
4. Select an output directory
5. Click "Extract Assets" to create a complete asset package

### Supported File Types
- **BSP Files**: Quake 3 format (IBSP version 46)
- **Shader Files**: Standard .shader files with full parsing support
- **Texture Formats**: .tga, .jpg, .jpeg, .png

## File Structure

### Input Structure
```
game_directory/
├── maps/
│   ├── your_map.bsp
│   └── other_maps.bsp
├── scripts/
│   ├── shaderlist.txt
│   ├── common.shader
│   └── custom.shader
└── textures/
    ├── common/
    ├── custom/
    └── subfolder/
```

### Output Structure
```
extracted_assets/
├── maps/
│   └── your_maps.bsp
├── scripts/
│   └── required_shaders.shader
├── textures/
│   ├── common/
│   └── custom/
└── asset_summary.txt
```

## Technical Details

### BSP File Format Support
- **Magic Number**: IBSP
- **Version**: 46 (Quake 3)
- **Lumps Parsed**: Textures (Lump 1), all 17 lumps for information display
- **Texture Extraction**: 64-byte null-terminated strings from texture lump

### Shader File Parsing
- **Comment Removal**: C-style comments (/* */) and line comments (//)
- **Block Structure**: Nested brace parsing for shader stages
- **Property Extraction**: Key-value pairs for shader properties
- **Stage Analysis**: Multi-stage shader support

### Asset Discovery Algorithm
1. Extract texture names from BSP files
2. Search for textures in specified directories with multiple naming conventions
3. Parse shader files to find definitions
4. Match textures to shaders and identify missing assets
5. Create organized directory structure with all required files

## Example Use Cases

### Map Packaging
Extract all assets needed for a custom map:
```
1. Select your .bsp file(s)
2. Point to your textures directory
3. Set scripts folder location
4. Extract to create a distributable package
```

### Asset Auditing
Find missing textures or unused shaders:
```
1. Analyze BSP file
2. Check "Shaders" tab for missing definitions
3. Review extraction log for unfound textures
```

### Batch Processing
Process multiple maps from a mod:
```
1. Select all BSP files from maps folder
2. Add multiple texture search paths
3. Extract everything to a single package
```

## Contributing

We welcome contributions! Please feel free to submit pull requests or open issues for:
- Bug fixes
- Feature enhancements
- Additional game engine support
- UI improvements
- Documentation updates

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Submit a pull request with a clear description

## Compatibility

### Game Engines
- **Primary**: ioquake3 and derivatives
- **Tested**: Quake 3 Arena, OpenArena, Urban Terror
- **Potential**: Any game using Q3BSP format

### Operating Systems
- Windows 10/11
- Linux (Ubuntu, Fedora, etc.)
- macOS 10.14+

## Troubleshooting

### Common Issues

**"Not a valid Quake 3 BSP file"**
- Ensure the file is actually a BSP file
- Check that it's Quake 3 format (not Quake 1/2 or other engines)

**"Could not find scripts folder automatically"**
- Manually browse to the scripts directory
- Ensure shader files have .shader extension
- Check directory permissions

**"No textures found"**
- Verify texture search paths are correct
- Check texture file extensions (.tga, .jpg, .png)
- Ensure textures aren't inside pak files

### Performance Notes
- Large BSP files (>50MB) may take several seconds to analyze
- Batch extraction performance depends on number of texture files
- Progress bars provide real-time feedback for long operations

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built for the Quake 3 modding community
- Inspired by various BSP analysis tools
- Thanks to id Software for open-sourcing the Quake 3 engine

## Version History

### v1.0.0
- Initial release
- Basic BSP parsing and texture extraction
- Shader file parsing
- GUI interface with tabbed layout
- Batch asset extraction
- Export functionality

---

*For support, feature requests, or bug reports, please open an issue on GitHub.*
