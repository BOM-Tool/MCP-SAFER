const multer = require('multer');
const path = require('path');
const fs = require('fs');

// uploads 디렉토리가 없으면 생성
const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// 파일 저장 설정
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // 파일명: 타임스탬프_원본파일명
    const uniqueSuffix = Date.now() + '_' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext);
    cb(null, `${uniqueSuffix}_${name}${ext}`);
  }
});

// 파일 필터 (필요시 확장)
const fileFilter = (req, file, cb) => {
  // 허용할 파일 타입 (예: 모든 파일 허용, 추후 제한 가능)
  const allowedTypes = /\.(zip|tar|gz|json|txt|sh|js)$/i;
  if (allowedTypes.test(file.originalname) || !file.originalname.includes('.')) {
    cb(null, true);
  } else {
    cb(new Error('허용되지 않은 파일 형식입니다.'), false);
  }
};

// 이미지 파일 필터
const imageFilter = (req, file, cb) => {
  // 이미지 파일 타입 허용
  const allowedTypes = /\.(jpg|jpeg|png|gif|webp|svg)$/i;
  const allowedMimeTypes = /^image\/(jpeg|jpg|png|gif|webp|svg\+xml)$/i;
  
  if (allowedTypes.test(file.originalname) || allowedMimeTypes.test(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('이미지 파일만 업로드 가능합니다. (jpg, jpeg, png, gif, webp, svg)'), false);
  }
};

// 이미지 업로드 설정
const imageStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '_' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext);
    cb(null, `img_${uniqueSuffix}_${name}${ext}`);
  }
});

const imageUpload = multer({
  storage: imageStorage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB 제한
  },
  fileFilter: imageFilter
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB 제한
  },
  fileFilter: fileFilter
});

module.exports = upload;
module.exports.imageUpload = imageUpload;
module.exports.fields = multer({
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB 제한
  },
  fileFilter: (req, file, cb) => {
    // file 필드는 기존 필터, image 필드는 이미지 필터 사용
    if (file.fieldname === 'image') {
      imageFilter(req, file, cb);
    } else {
      fileFilter(req, file, cb);
    }
  }
}).fields([
  { name: 'file', maxCount: 1 },
  { name: 'image', maxCount: 1 }
]);

