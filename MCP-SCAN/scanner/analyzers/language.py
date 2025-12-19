from pathlib import Path
from typing import List, Dict, Set
from scanner.analyzers.common.scanner import ConfigLoader

class LanguageConfig:

    EXTENSIONS: Dict[str, List[str]] = {
        'go': ['.go'],
        'ts': ['.ts', '.tsx', '.js', '.jsx'],
    }

    INDICATORS: Dict[str, List[str]] = {
        'go': ['package main', 'import', 'func ', 'var ', 'type '],
        'ts': ['import ', 'export ', 'interface ', 'type ', 'function '],
    }
    
    @staticmethod
    def get_exclude_dirs(language: str) -> Set[str]:
        config = ConfigLoader.get_instance()
        exclude_list = config.get_exclude_dirs(language)
        return set(exclude_list)
    
    EXCLUDE_DIRS: Dict[str, Set[str]] = {
        'go': {'vendor', 'node_modules', '__pycache__'},
        'ts': {'node_modules', 'dist', 'build', '__pycache__'},
    }

    DISPLAY_NAMES: Dict[str, str] = {
        'go': 'Go',
        'ts': 'TypeScript/JavaScript',
    }
    
    @classmethod
    def get_language_from_extension(cls, extension: str) -> str:
        ext_lower = extension.lower()
        if not ext_lower.startswith('.'):
            ext_lower = f'.{ext_lower}'
        
        for lang, extensions in cls.EXTENSIONS.items():
            if ext_lower in extensions:
                return lang
        
        return 'unknown'
    
    @classmethod
    def get_display_name(cls, language: str) -> str:
        return cls.DISPLAY_NAMES.get(language, 'Unknown')
    
    @classmethod
    def get_all_supported_languages(cls) -> List[str]:
        return list(cls.EXTENSIONS.keys())
    
    @classmethod
    def is_supported(cls, language: str) -> bool:
        return language in cls.EXTENSIONS


class FileScanner:
    
    @staticmethod
    def scan_files(repo_path: Path, extensions: List[str], exclude_dirs: Set[str]) -> List[Path]:
        files = []
        
        for file_path in repo_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            if any(excluded in file_path.parts for excluded in exclude_dirs):
                continue
            
            if file_path.suffix.lower() in extensions:
                files.append(file_path)
        
        return sorted(files)
    
    @staticmethod
    def has_files_with_extension(repo_path: Path, extensions: List[str], exclude_dirs: Set[str]) -> bool:
        for file_path in repo_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            if any(excluded in file_path.parts for excluded in exclude_dirs):
                continue
            
            if file_path.suffix.lower() in extensions:
                return True
        
        return False


class ContentValidator:
    
    @staticmethod
    def validate_language_content(repo_path: Path, language: str, max_files: int = 10) -> bool:
        extensions = LanguageConfig.EXTENSIONS[language]
        indicators = LanguageConfig.INDICATORS[language]
        exclude_dirs = LanguageConfig.get_exclude_dirs(language)
        
        found_indicators = 0
        checked_files = 0
        
        for file_path in repo_path.rglob('*'):
            if not file_path.is_file() or file_path.suffix.lower() not in extensions:
                continue
            
            if any(excluded in file_path.parts for excluded in exclude_dirs):
                continue
            
            checked_files += 1
            if checked_files > max_files:
                break
            
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                for indicator in indicators:
                    if indicator in content:
                        found_indicators += 1
                        break
            except Exception:
                continue
        
        return found_indicators > 0

class LanguageDetector:

    def __init__(self):
        self.file_scanner = FileScanner()
        self.content_validator = ContentValidator()
    
    def detect(self, repo_path: Path) -> List[str]:
        detected_languages: Set[str] = set()
        
        for language in LanguageConfig.get_all_supported_languages():
            extensions = LanguageConfig.EXTENSIONS[language]
            exclude_dirs = LanguageConfig.get_exclude_dirs(language)
            
            if self.file_scanner.has_files_with_extension(repo_path, extensions, exclude_dirs):
                detected_languages.add(language)
        
        final_languages = []
        for lang in detected_languages:
            if self.content_validator.validate_language_content(repo_path, lang):
                final_languages.append(lang)
        
        return sorted(final_languages)
    
    def detect_from_file(self, file_path: Path) -> str:
        return LanguageConfig.get_language_from_extension(file_path.suffix)
    
    def detect_from_path(self, file_path: str) -> str:
        path_obj = Path(file_path)
        lang_code = LanguageConfig.get_language_from_extension(path_obj.suffix)
        return LanguageConfig.get_display_name(lang_code)
    
    def get_file_list(self, repo_path: Path, language: str) -> List[Path]:
        if not LanguageConfig.is_supported(language):
            return []
        
        extensions = LanguageConfig.EXTENSIONS[language]
        exclude_dirs = LanguageConfig.get_exclude_dirs(language)
        
        return self.file_scanner.scan_files(repo_path, extensions, exclude_dirs)