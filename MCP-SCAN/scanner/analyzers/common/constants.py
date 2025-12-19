from pathlib import Path

ARTIFACTS_DIR = Path("artifacts")
TEMP_DIR = ARTIFACTS_DIR / "temp"
OUTPUT_DIR = Path("output")
REPOSITORIES_FILE = Path("test/repositories.txt")

GITHUB_PREFIXES = ('https://github.com/', 'http://github.com/')
GITHUB_DEPTH = 1
CLONE_RETRIES = 3

SUPPORTED_LANGUAGES = ["go", "ts"]
UNKNOWN_LANGUAGE = "unknown"

PROGRESS_PREPARE_START = 10
PROGRESS_DETECT_LANGS = 37
PROGRESS_SCAN_START = 40
PROGRESS_SCAN_END = 85
PROGRESS_FINALIZING = 95
PROGRESS_COMPLETE = 100

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

EXCLUDE_SEVERITIES = [SEVERITY_INFO]

LANGUAGE_EXTENSIONS = {
    "go": [".go"],
    "ts": [".ts", ".tsx", ".js", ".jsx"],
}

TEST_FILE_PATTERNS = [
    '_test.', '.test.', '.spec.', '/test/', '/tests/', 
    '/__tests__/', '/testdata/', 'test/', 'tests/'
]

CONFIDENCE_LEVELS = {
    'INFO': 0.1,
    'LOW': 0.3,
    'MEDIUM': 0.6,
    'HIGH': 0.9,
    'CRITICAL': 1.0
}

SEVERITY_WEIGHTS = {
    SEVERITY_INFO: 1,
    SEVERITY_LOW: 2,
    SEVERITY_MEDIUM: 4,
    SEVERITY_HIGH: 7,
    SEVERITY_CRITICAL: 10,
}