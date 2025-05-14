---
marp: true
theme: default
paginate: true
backgroundColor: #fff
backgroundImage: url('https://marp.app/assets/hero-background.svg')
---

# Express.js 백엔드 서버 분석
## 라우터, 미들웨어, 컨트롤러의 역할과 상호작용

---

## 목차

1. 프로젝트 구조 개요
2. 라우터(Router): 경로 관리와 요청 분배
3. 미들웨어(Middleware): 요청 처리 중간 단계
4. 컨트롤러(Controller): 비즈니스 로직 처리
5. 모델(Model): 데이터 구조 정의
6. 유틸리티(Utility): 헬퍼 기능
7. 전체 요청 처리 흐름

---

## 프로젝트 구조

Express.js 백엔드는 MVC 패턴을 기반으로 구성되어 있습니다:

```
server/
├── config/          # 설정 파일
│   ├── db.js        # MongoDB 연결 설정
│   └── swagger.js   # API 문서화 설정
├── controllers/     # 비즈니스 로직
│   ├── authController.js    # 인증 관련 로직
│   ├── postController.js    # 게시글 관련 로직
│   ├── commentController.js # 댓글 관련 로직
│   ├── userController.js    # 사용자 관리 로직
│   └── aiController.js      # AI 응답 생성 로직
├── middleware/      # 미들웨어
│   ├── auth.js      # 인증 미들웨어
│   └── errorHandler.js # 오류 처리 미들웨어
├── models/          # 데이터 모델
│   ├── User.js      # 사용자 모델
│   ├── Post.js      # 게시글 모델
│   └── Comment.js   # 댓글 모델
├── routes/          # 라우터
│   ├── authRoutes.js    # 인증 관련 경로
│   ├── postRoutes.js    # 게시글 관련 경로
│   ├── commentRoutes.js # 댓글 관련 경로
│   ├── userRoutes.js    # 사용자 관리 경로
│   └── aiRoutes.js      # AI 기능 경로
├── utils/           # 유틸리티 함수
│   ├── fileUpload.js    # 파일 업로드 기능
│   └── openai.js        # OpenAI API 통신
├── app.js           # Express 앱 설정
└── server.js        # 서버 시작 파일
```

---

## app.js: Express 애플리케이션 설정

```javascript
const express = require('express');
const cors = require('cors');
const app = express();

// 전역 미들웨어 등록
app.use(express.json());
app.use(cors({ origin: "http://localhost:5173", credentials: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 라우터 등록
app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/posts', postRoutes);
app.use('/comments', commentRoutes);

// 오류 처리 미들웨어
app.use(errorHandler);

module.exports = app;
```

---

## server.js: 서버 시작

```javascript
const app = require('./app');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

// 환경 변수 로드
dotenv.config();
const PORT = process.env.PORT || 5000;

// 서버 시작 함수
const startServer = () => {
  app.listen(PORT, () => {
    console.log(`서버가 ${PORT} 포트에서 실행 중입니다`);
  });
};

// MongoDB 연결 후 서버 시작
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB에 연결되었습니다');
    startServer();
  })
  .catch(err => {
    console.error('MongoDB 연결 오류:', err.message);
    process.exit(1);
  });
```

---

## 1. 라우터(Router) 개요

- URL 경로와 HTTP 메서드를 기반으로 요청을 분류하는 역할
- 각 경로에 적절한 컨트롤러 함수를 연결
- 필요한 미들웨어를 경로별로 적용 가능

---

## 라우터 작동 방식

라우터는 **경로 정의**(URI + HTTP 메서드) → **미들웨어 적용** → **컨트롤러 실행** 순서로 작동합니다.

```
클라이언트 요청 → 라우터 → (미들웨어) → 컨트롤러 → 응답
```

실생활 비유: **우체국 분류 시스템**
- 우편물(요청)에 적힌 주소(URL)에 따라 
- 적절한 담당자(컨트롤러)에게 전달

---

## 라우터 예시: 인증 라우터

```javascript
// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect } = require('../middleware/auth');

// 회원가입 - POST /auth/register
router.post('/register', authController.register);

// 로그인 - POST /auth/login
router.post('/login', authController.login);

// 로그아웃 - GET /auth/logout
router.get('/logout', authController.logout);

// 사용자 정보 - GET /auth/me (인증 필요)
router.get('/me', protect, authController.getMe);

module.exports = router;
```

---

## 라우터 예시: 게시글 라우터

```javascript
// routes/postRoutes.js
const router = express.Router();
const { protect, checkOwnership } = require('../middleware/auth');
const Post = require('../models/Post');

// 모든 게시글 조회 및 게시글 생성
router.route('/')
  .get(postController.getPosts)
  .post(protect, upload.array('files', 3), postController.createPost);

// 특정 게시글 조회, 수정, 삭제
router.route('/:id')
  .get(postController.getPost)
  .put(protect, checkOwnership(Post), postController.updatePost)
  .delete(protect, checkOwnership(Post), postController.deletePost);

// 게시글 좋아요/좋아요 취소
router.put('/:id/like', protect, postController.toggleLike);
```

---

## 라우터 사용법

`app.js`에서 라우터를 기본 경로와 함께 등록합니다:

```javascript
// app.js
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const postRoutes = require('./routes/postRoutes');
const commentRoutes = require('./routes/commentRoutes');

// API 라우트 등록
app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/posts', postRoutes);
app.use('/comments', commentRoutes);
```

`app.use('/auth', authRoutes)` 의미:
- '/auth'로 시작하는 모든 요청은 authRoutes가 처리
- 예: '/auth/login', '/auth/register' 등

---

## 2. 미들웨어(Middleware) 개요

- 요청과 응답 사이에서 실행되는 함수들
- 요청 객체(req), 응답 객체(res), 다음 미들웨어 호출 함수(next)를 인자로 받음
- `next()`를 호출하면 다음 미들웨어로 제어권이 넘어감

---

## 미들웨어 작동 방식

미들웨어는 **요청 전처리** → **응답 생성 또는 다음 미들웨어 호출**의 순서로 작동합니다.

```
요청 → 미들웨어1 → 미들웨어2 → ... → 라우트 핸들러 → 응답
```

실생활 비유: **공장의 조립 라인**
- 각 작업대(미들웨어)는 특정 작업만 수행
- 작업이 끝나면 다음 작업대로 제품을 전달

---

## 미들웨어 유형

1. **애플리케이션 레벨 미들웨어**: `app.use()`
   ```javascript
   app.use(express.json());
   app.use(cors());
   ```

2. **라우터 레벨 미들웨어**: 특정 라우터에만 적용
   ```javascript
   router.use(loggerMiddleware);
   ```

3. **경로 레벨 미들웨어**: 특정 경로에만 적용
   ```javascript
   router.get('/profile', authMiddleware, profileController);
   ```

4. **오류 처리 미들웨어**: 4개의 인자를 가짐
   ```javascript
   app.use((err, req, res, next) => { /* 오류 처리 */ });
   ```

---

## 미들웨어 예시: 인증 미들웨어

```javascript
// middleware/auth.js
exports.protect = async (req, res, next) => {
  let token;

  // 헤더에서 Authorization 토큰 확인
  if (req.headers.authorization?.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  // 토큰이 없으면 접근 거부
  if (!token) {
    return res.status(401).json({
      success: false,
      message: '이 리소스에 접근하려면 로그인이 필요합니다'
    });
  }

  try {
    // 토큰 검증 및 사용자 정보 가져오기
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: '사용자를 찾을 수 없습니다'
      });
    }

    next(); // 다음 미들웨어로 진행
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: '인증에 실패했습니다'
    });
  }
};
```

---

## 미들웨어 예시: 소유권 검사 미들웨어

```javascript
// middleware/auth.js
exports.checkOwnership = (model) => async (req, res, next) => {
  try {
    const resource = await model.findById(req.params.id);

    if (!resource) {
      return res.status(404).json({
        success: false,
        message: '리소스를 찾을 수 없습니다'
      });
    }

    // 관리자는 모든 리소스에 접근 가능
    if (req.user.role === 'admin') {
      req.resource = resource;
      return next();
    }

    // 소유자 확인
    const ownerId = resource.author || resource.user;
    
    if (ownerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: '이 리소스에 대한 권한이 없습니다'
      });
    }

    // 리소스를 req 객체에 추가 (컨트롤러에서 사용)
    req.resource = resource;
    next();
  } catch (err) {
    next(err);
  }
};
```

---

## 에러 처리 미들웨어

```javascript
// middleware/errorHandler.js
exports.errorHandler = (err, req, res, next) => {
  console.error(err);
  
  let error = { ...err };
  error.message = err.message;
  
  // Mongoose 잘못된 ObjectId
  if (err.name === 'CastError') {
    error = { message: '리소스를 찾을 수 없습니다', statusCode: 404 };
  }
  
  // Mongoose 중복 키 에러
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    error = { message: `${field} 필드의 값이 이미 사용 중입니다`, statusCode: 400 };
  }
  
  // Mongoose 유효성 검사 실패
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(val => val.message);
    error = { message, statusCode: 400 };
  }
  
  // 응답 반환
  res.status(error.statusCode || 500).json({
    success: false,
    message: error.message || '서버 에러',
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
  });
};
```

---

## 비동기 핸들러 유틸리티

에러 처리 미들웨어와 함께 비동기 함수의 오류를 캐치하는 유틸리티:

```javascript
// middleware/errorHandler.js
exports.asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
```

사용 예시:
```javascript
exports.getPost = asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);
  
  if (!post) {
    return res.status(404).json({
      success: false,
      message: '게시글을 찾을 수 없습니다'
    });
  }
  
  res.status(200).json({
    success: true,
    data: post
  });
});
```

---

## 3. 컨트롤러(Controller) 개요

- 비즈니스 로직을 처리하는 함수들
- 요청에서 데이터를 추출하여 처리
- 데이터베이스 작업 수행
- 클라이언트에게 응답 반환

---

## 컨트롤러 작동 방식

컨트롤러는 **요청 데이터 추출** → **비즈니스 로직 처리** → **응답 반환**의 순서로 작동합니다.

실생활 비유: **레스토랑 주방장**
- 주문(요청)을 받아서
- 음식(데이터)을 준비하고
- 손님(클라이언트)에게 음식(응답)을 제공

---

## 컨트롤러 예시: 로그인 컨트롤러

```javascript
// controllers/authController.js
exports.login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // 1. 요청 데이터 검증
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: '이메일과 비밀번호를 입력해주세요'
    });
  }

  // 2. 사용자 조회
  const user = await User.findOne({ email }).select('+password');

  // 3. 사용자 존재 여부 확인
  if (!user) {
    return res.status(401).json({
      success: false,
      message: '유효하지 않은 인증 정보입니다'
    });
  }

  // 4. 비밀번호 확인
  const isMatch = await user.matchPassword(password);
  if (!isMatch) {
    return res.status(401).json({
      success: false,
      message: '유효하지 않은 인증 정보입니다'
    });
  }

  // 5. JWT 토큰 생성 및 응답
  sendTokenResponse(user, 200, res);
});
```

---

## 컨트롤러 예시: 게시글 조회

```javascript
// controllers/postController.js
exports.getPost = asyncHandler(async (req, res) => {
  // 게시글 ID로 조회
  const post = await Post.findById(req.params.id)
    .populate({
      path: 'author',
      select: 'username nickname profileImage'
    });
  
  // 게시글 존재 확인
  if (!post) {
    return res.status(404).json({
      success: false,
      message: '게시글을 찾을 수 없습니다'
    });
  }
  
  // 댓글 정보 조회
  if (post.comments && post.comments.length > 0) {
    await post.populate({
      path: 'comments',
      populate: {
        path: 'author',
        select: 'username nickname profileImage'
      }
    });
  }
  
  // 조회수 증가
  post.viewCount += 1;
  await post.save({ validateBeforeSave: false });

  // 응답 반환
  res.status(200).json({
    success: true,
    data: post
  });
});
```

---

## 컨트롤러 예시: 게시글 생성

```javascript
// controllers/postController.js
exports.createPost = asyncHandler(async (req, res) => {
  const { title, content, categories, tags } = req.body;
  
  // 카테고리와 태그 처리
  const categoriesArray = Array.isArray(categories) 
    ? categories 
    : categories.split(',').map(c => c.trim());
  
  const tagsArray = Array.isArray(tags) 
    ? tags 
    : tags.split(',').map(t => t.trim());
  
  // 첨부파일 처리
  const attachments = req.files ? req.files.map(file => ({
    filename: file.filename,
    originalname: file.originalname,
    path: `/uploads/post-attachments/${file.filename}`,
    mimetype: file.mimetype,
    size: file.size
  })) : [];
  
  // 게시글 생성
  const post = await Post.create({
    title,
    content,
    author: req.user.id,
    categories: categoriesArray,
    tags: tagsArray,
    attachments
  });

  // 응답
  res.status(201).json({
    success: true,
    data: post
  });
});
```

---

## 4. 모델(Model) 개요

- MongoDB 스키마를 정의하는 파일
- 데이터 구조, 유효성 검사 규칙 정의
- 데이터 관련 메서드 구현
- Mongoose를 사용하여 MongoDB와 상호작용

---

## 모델 예시: 사용자 모델

```javascript
// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, '사용자 이름은 필수입니다'],
    unique: true,
    trim: true,
    minlength: [3, '사용자 이름은 최소 3자 이상이어야 합니다'],
    maxlength: [20, '사용자 이름은 최대 20자까지 가능합니다'],
  },
  email: {
    type: String,
    required: [true, '이메일은 필수입니다'],
    unique: true,
    match: [
      /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/,
      '유효한 이메일 주소를 입력해주세요',
    ],
  },
  password: {
    type: String,
    required: [true, '비밀번호는 필수입니다'],
    minlength: [6, '비밀번호는 최소 6자 이상이어야 합니다'],
    select: false, // 기본적으로 조회 결과에 포함되지 않음
  },
  // 기타 필드...
}, { timestamps: true });
```

---

## 모델 메서드 및 미들웨어

```javascript
// models/User.js (계속)

// 비밀번호 해싱 미들웨어
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// 비밀번호 확인 메서드
UserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// JWT 토큰 생성 메서드
UserSchema.methods.getSignedJwtToken = function () {
  return jwt.sign(
    { id: this._id, role: this.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE }
  );
};

module.exports = mongoose.model('User', UserSchema);
```

---

## 모델 예시: 게시글 모델

```javascript
// models/Post.js
const mongoose = require('mongoose');

const PostSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, '제목은 필수입니다'],
    trim: true,
    maxlength: [100, '제목은 최대 100자까지 가능합니다'],
  },
  content: {
    type: String,
    required: [true, '내용은 필수입니다'],
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  categories: {
    type: [String],
    default: ['기타'],
    enum: ['수학', '물리학', '화학', '생물학', '컴퓨터공학', '전자공학', '기계공학', '경영학', '경제학', '심리학', '사회학', '기타']
  },
  // 기타 필드...
}, { timestamps: true, toJSON: { virtuals: true } });

// 가상 필드: 좋아요 수
PostSchema.virtual('likeCount').get(function () {
  return this.likes.length;
});
```

---

## 5. 유틸리티(Utility) 함수

프로젝트에서 재사용 가능한 다양한 헬퍼 함수들을 제공합니다.

1. **파일 업로드 유틸리티** (multer 설정)
2. **OpenAI API 연동 유틸리티**
3. **JWT 토큰 관리**
4. **에러 처리 유틸리티**

---

## 파일 업로드 유틸리티

```javascript
// utils/fileUpload.js
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

// 안전한 파일명 생성
const generateSafeFilename = (originalname) => {
  const extension = path.extname(originalname);
  const timestamp = Date.now();
  const randomString = crypto.randomBytes(8).toString('hex');
  return `${path.basename(originalname, extension).substring(0, 50)}_${timestamp}_${randomString}${extension}`;
};

// 프로필 이미지 저장 설정
const profileImageStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '..', 'uploads/profile-images'));
  },
  filename: (req, file, cb) => {
    const safeFilename = generateSafeFilename(file.originalname);
    cb(null, `profile_${req.user.id}_${safeFilename}`);
  }
});

// Multer 설정 내보내기
const upload = {
  profileImage: multer({
    storage: profileImageStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: imageFilter
  }),
  // 기타 업로드 설정...
};
```

---

## OpenAI API 유틸리티

```javascript
// utils/openai.js
class OpenAIClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseURL = 'https://api.openai.com/v1';
  }

  async generateResponse(content, title, category, tags = []) {
    try {
      // 시스템 및 사용자 프롬프트 생성
      const systemPrompt = this.createSystemPrompt(category);
      const userPrompt = this.createUserPrompt(content, title, category, tags);
      
      const response = await axios.post(
        `${this.baseURL}/chat/completions`,
        {
          model: 'gpt-4',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt }
          ],
          max_tokens: 500,
          temperature: 0.7,
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`
          }
        }
      );

      return response.data.choices[0].message.content;
    } catch (error) {
      console.error('OpenAI API 오류:', error.message);
      throw new Error('AI 응답 생성 실패');
    }
  }
  
  // 기타 메서드...
}
```

---

## 6. 전체 요청 처리 흐름

![height:450px](https://example.com/flow-diagram.png)

1. **클라이언트에서 요청 전송** (`POST /posts/123/comments`)
2. **Express 앱**이 요청을 받아 전역 미들웨어 적용 (JSON 파싱, CORS 등)
3. **라우터**가 경로에 맞는 핸들러로 요청 전달 (`commentRoutes.js`)
4. **인증 미들웨어**가 JWT 토큰을 검증하고 사용자 정보 추가
5. **컨트롤러**가 비즈니스 로직 처리 (`commentController.createComment`)
6. **모델**을 통해 데이터베이스 작업 수행 (`Comment.create()`)
7. **컨트롤러**가 응답 생성 (`res.status(201).json({...})`)
8. **클라이언트**가 응답 수신

---

## 요약: 서버의 핵심 요소

- **라우터(Router)**: 요청을 적절한 핸들러로 전달하는 분배기
- **미들웨어(Middleware)**: 요청 처리 과정의 중간 단계 함수들
- **컨트롤러(Controller)**: 비즈니스 로직을 처리하는 함수들
- **모델(Model)**: 데이터 구조와 유효성 검사 규칙 정의
- **유틸리티(Utility)**: 공통 기능을 제공하는 헬퍼 함수들

각 구성 요소는 단일 책임 원칙에 따라 명확한 역할을 수행하며, 함께 작동하여 완전한 백엔드 시스템을 구성합니다.

---

## 질문 & 답변

백엔드 개발 및 Express.js에 대한 질문이 있으신가요?

감사합니다!
