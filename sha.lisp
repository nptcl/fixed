(defpackage sha
  (:use common-lisp)
  (:export
    #:sha32fixnum
    #:sha64fixnum
    #:sha32encode

    ;;  sha256encode
    #:make-sha256encode
    #:init-sha256encode
    #:byte-sha256encode
    #:little-endian-sha256encode
    #:big-endian-sha256encode
    #:calc-sha256encode

    ;;  sha3encode
    #:make-sha3-224-encode
    #:make-sha3-256-encode
    #:make-sha3-384-encode
    #:make-sha3-512-encode
    #:make-shake-128-encode
    #:make-shake-256-encode
    #:init-sha3encode
    #:byte-sha3encode
    #:little-endian-sha3encode
    #:big-endian-sha3encode
    #:result-sha3encode
    #:calc-sha3encode
    ))

(in-package sha)

(deftype sha32fixnum ()
  '(unsigned-byte 32))

(deftype sha64fixnum ()
  '(unsigned-byte 64))

(defun make-array8 (n)
  (make-array n :element-type '(unsigned-byte 8)))

(defun make-array32 (n)
  (make-array n :element-type 'sha32fixnum :initial-element 0))

(defun make-array64 (n)
  (make-array n :element-type 'sha64fixnum :initial-element 0))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  SHA-2: sha32encode
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defconstant +sha32-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))

(defconstant +sha32-h+
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19))

(defstruct sha32encode
  (h (make-array32 8))
  (w (make-array32 16))
  (index 0)
  (size 0))

(defun sha32-clear-w (array-w)
  (dotimes (i 16)
    (setf (aref array-w i) 0)))

(defmacro sha32-mask (x)
  `(logand ,x #xFFFFFFFF))

(defmacro sha32-add (&rest args)
  `(sha32-mask (+ ,@args)))

(defun sha32-ch (x y z)
  (declare (type sha32fixnum x y z))
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha32-maj (x y z)
  (declare (type sha32fixnum x y z))
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha32-rotl (x n)
  (declare (type sha32fixnum x))
  (sha32-mask
    (logior (ash x n) (ash x (- n 32)))))

(defun sha32-rotr (x n)
  (declare (type sha32fixnum x))
  (sha32-mask
    (logior (ash x (- 32 n)) (ash x (- n)))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  SHA-2: 256 bit
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defun make-sha256encode ()
  (let* ((sha (make-sha32encode))
         (array-h (sha32encode-h sha)))
    (dotimes (i 8)
      (setf (aref array-h i) (aref +sha32-h+ i)))
    sha))

(defun init-sha256encode (sha)
  (let ((array-h (sha32encode-h sha))
        (array-w (sha32encode-w sha)))
    (dotimes (i 8)
      (setf (aref array-h i) (aref +sha32-h+ i)))
    (sha32-clear-w array-w)
    (setf (sha32encode-index sha) 0)
    (setf (sha32encode-size sha) 0))
  (values))

(defun sigma32-upper-0 (x)
  (declare (type sha32fixnum x))
  (logxor (sha32-rotr x 2) (sha32-rotr x 13) (sha32-rotr x 22)))

(defun sigma32-upper-1 (x)
  (declare (type sha32fixnum x))
  (logxor (sha32-rotr x 6) (sha32-rotr x 11) (sha32-rotr x 25)))

(defun sigma32-lower-0 (x)
  (declare (type sha32fixnum x))
  (logxor (sha32-rotr x 7) (sha32-rotr x 18) (ash x -3)))

(defun sigma32-lower-1 (x)
  (declare (type sha32fixnum x))
  (logxor (sha32-rotr x 17) (sha32-rotr x 19) (ash x -10)))

(defun sha256-w (array-w s)
  (setf (aref array-w s)
        (sha32-add
          (sigma32-lower-1 (aref array-w (logand (+ s 14) #x0F)))
          (aref array-w (logand (+ s 9) #x0F))
          (sigma32-lower-0 (aref array-w (logand (+ s 1) #x0F)))
          (aref array-w s))))

(defmacro sha256-x (e f g h i ws)
  `(sha32-add ,h
              (sigma32-upper-1 ,e)
              (sha32-ch ,e ,f ,g)
              (aref +sha32-k+ ,i)
              ,ws))

(defmacro sha256-y (a b c)
  `(sha32-add (sigma32-upper-0 ,a)
              (sha32-maj ,a ,b ,c)))

(defmacro sha256-abcdefgh (a b c d e f g h x y)
  `(setq ,h ,g ,g ,f ,f ,e ,e (sha32-add ,d ,x)
         ,d ,c ,c ,b ,b ,a ,a (sha32-add ,x ,y)))

(defun sha32-incf (array-h index value)
  (setf (aref array-h index) (sha32-add (aref array-h index) value)))

(defun next-sha256encode (sha)
  (let* ((array-h (sha32encode-h sha))
         (array-w (sha32encode-w sha))
         (a (aref array-h 0))
         (b (aref array-h 1))
         (c (aref array-h 2))
         (d (aref array-h 3))
         (e (aref array-h 4))
         (f (aref array-h 5))
         (g (aref array-h 6))
         (h (aref array-h 7)))
    (declare (type sha32fixnum a b c d e f g h))

    ;;  0 - 15
    (loop for i from 0 below 16
          do (let* ((ws (aref array-w i))
                    (x (sha256-x e f g h i ws))
                    (y (sha256-y a b c)))
               (sha256-abcdefgh a b c d e f g h x y)))

    ;;  16 - 63
    (loop for i from 16 below 64
          do (let* ((s (logand i #x0F))
                    (ws (sha256-w array-w s))
                    (x (sha256-x e f g h i ws))
                    (y (sha256-y a b c)))
               (sha256-abcdefgh a b c d e f g h x y)))

    ;;  add
    (sha32-incf array-h 0 a)
    (sha32-incf array-h 1 b)
    (sha32-incf array-h 2 c)
    (sha32-incf array-h 3 d)
    (sha32-incf array-h 4 e)
    (sha32-incf array-h 5 f)
    (sha32-incf array-h 6 g)
    (sha32-incf array-h 7 h)

    ;;  clear-w
    (sha32-clear-w array-w)))

(defun byte-sha256encode (sha v)
  (declare (type sha32encode sha)
           (type (unsigned-byte 8) v))
  (let ((w (sha32encode-w sha))
        (i (sha32encode-index sha)))
    (multiple-value-bind (x y) (truncate i 4)
      (setq y (- 4 y 1))
      (setf (aref w x) (logior (aref w x) (ash v (* y 8)))))
    (incf i 1)

    ;;  next
    (unless (< i 64)
      (next-sha256encode sha)
      (setq i 0))
    (setf (sha32encode-index sha) i)
    (incf (sha32encode-size sha) 1)))

(defun little-endian-sha256encode (sha x size)
  (dotimes (i size)
    (byte-sha256encode sha (ldb (byte 8 (* i 8)) x))))

(defun big-endian-sha256encode (sha x size)
  (dotimes (k size)
    (let ((i (- size k 1)))
      (byte-sha256encode sha (ldb (byte 8 (* i 8)) x)))))

(defun finish-sha256encode (sha)
  (let ((size (* (sha32encode-size sha) 8)))
    (byte-sha256encode sha #x80)
    (when (< (- 64 8) (sha32encode-index sha))
      (next-sha256encode sha))
    (let ((w (sha32encode-w sha)))
      (setf (aref w (- 16 2)) (sha32-mask (ash size -32)))
      (setf (aref w (- 16 1)) (sha32-mask size))
      (next-sha256encode sha))))

(defun calc-sha256encode (sha &optional a)
  (finish-sha256encode sha)
  (unless a
    (setq a (make-array8 32)))
  (let ((array-h (sha32encode-h sha)) (k 0))
    (dotimes (x 8)
      (let ((v (aref array-h x)))
        (dotimes (y 4)
          (let ((z (- 4 y 1)))
            (setf (aref a k) (logand (ash v (- (* z 8))) #xFF))
            (incf k 1)))))
    a))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  SHA-3
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defstruct (sha3encode (:constructor empty-sha3encode))
  (a (make-array64 25))
  (b (make-array64 25))
  (c (make-array64 5))
  (index 0)
  (rbyte 0)
  (dbyte 0)
  tail)

(defconstant +sha3-rho+
  #(0   1   62  28  27
    36  44  6   55  20
    3   10  43  25  39
    41  45  15  21  8
    18  2   61  56  14))

(defconstant +sha3-rc+
  #(#x0000000000000001 #x0000000000008082
    #x800000000000808A #x8000000080008000
    #x000000000000808B #x0000000080000001
    #x8000000080008081 #x8000000000008009
    #x000000000000008A #x0000000000000088
    #x0000000080008009 #x000000008000000A
    #x000000008000808B #x800000000000008B
    #x8000000000008089 #x8000000000008003
    #x8000000000008002 #x8000000000000080
    #x000000000000800A #x800000008000000A
    #x8000000080008081 #x8000000000008080
    #x0000000080000001 #x8000000080008008))

(defmacro sha3-xy (x y)
  `(+ (* 5 ,y) ,x))

(defmacro sha64-mask (x)
  `(logand ,x #xFFFFFFFFFFFFFFFF))

(defun sha64-rotl (x n)
  (declare (type sha64fixnum x))
  (sha64-mask
    (logior (ash x n) (ash x (- n 64)))))

(defun round-sha3encode (sha index)
  (let ((a (sha3encode-a sha))
        (b (sha3encode-b sha))
        (c (sha3encode-c sha)))
    ;;  theta
    (dotimes (x 5)
      (setf (aref c x)
            (logxor (aref a (sha3-xy x 0))
                    (aref a (sha3-xy x 1))
                    (aref a (sha3-xy x 2))
                    (aref a (sha3-xy x 3))
                    (aref a (sha3-xy x 4)))))
    (dotimes (x 5)
      (let* ((x1 (if (zerop x) 4 (1- x)))
             (x2 (mod (1+ x) 5))
             (v (logxor (aref c x1) (sha64-rotl (aref c x2) 1))))
        (dotimes (y 5)
          (let ((i (sha3-xy x y)))
            (setf (aref a i) (logxor (aref a i) v))))))
    ;;  rho, pi
    (dotimes (x 5)
      (dotimes (y 5)
        (let* ((xy (mod (+ (* 2 x) (* 3 y)) 5))
               (p (sha3-xy x y))
               (q (sha3-xy y xy))
               (v1 (aref a p))
               (v2 (aref +sha3-rho+ p)))
          (setf (aref b q) (sha64-rotl v1 v2)))))
    ;;  chi
    (dotimes (y 5)
      (dotimes (x 5)
        (setf (aref c x) (aref b (sha3-xy x y))))
      (dotimes (x 5)
        (let* ((v1 (aref c x))
               (v2 (aref c (mod (+ x 1) 5)))
               (v3 (aref c (mod (+ x 2) 5)))
               (v (logxor v1 (logand (lognot v2) v3))))
          (setf (aref a (sha3-xy x y)) v))))
    ;;  iota
    (let ((p (sha3-xy 0 0))
          (v (aref +sha3-rc+ index)))
      (setf (aref a p) (logxor (aref a p) v)))))

(defun next-sha3encode (sha)
  (setf (sha3encode-index sha) 0)
  (dotimes (i 24)
    (round-sha3encode sha i)))

(defun putc-sha3encode (a i v)
  (multiple-value-bind (x y) (truncate i 8)
    (setf (aref a x) (logxor (aref a x) (ash v (* y 8)))))
  v)

(defun getc-sha3encode (a i)
  (multiple-value-bind (x y) (truncate i 8)
    (ldb (byte 8 (* y 8)) (aref a x))))

(defun byte-sha3encode (sha v)
  (declare (type (unsigned-byte 8) v))
  (let ((i (sha3encode-index sha))
        (a (sha3encode-a sha)))
    (putc-sha3encode a i v)
    (incf i 1)
    (if (< i (sha3encode-rbyte sha))
      (setf (sha3encode-index sha) i)
      (next-sha3encode sha)))
  (values))

(defun little-endian-sha3encode (sha x size)
  (dotimes (i size)
    (byte-sha3encode sha (ldb (byte 8 (* i 8)) x))))

(defun big-endian-sha3encode (sha x size)
  (dotimes (k size)
    (let ((i (- size k 1)))
      (byte-sha3encode sha (ldb (byte 8 (* i 8)) x)))))

(defun finish-sha3encode (sha)
  (let ((v (ecase (sha3encode-tail sha)
             (sha3encode-01 #x06)
             (sha3encode-11 #x07)
             (sha3encode-1111 #x1F)))
        (a (sha3encode-a sha)))
    (putc-sha3encode a (sha3encode-index sha) v)
    (putc-sha3encode a (1- (sha3encode-rbyte sha)) #x80))
  (next-sha3encode sha))

(defun result-sha3encode (sha n &optional p)
  (unless p
    (setq p (make-array8 n)))
  (finish-sha3encode sha)
  (let ((rbyte (sha3encode-rbyte sha))
        (a (sha3encode-a sha))
        (k 0))
    (multiple-value-bind (y z) (truncate n rbyte)
      ;;  y
      (dotimes (x y)
        (unless (zerop k)
          (next-sha3encode sha))
        (dotimes (i rbyte)
          (setf (aref p k) (getc-sha3encode a i))
          (incf k 1)))
      ;;  z
      (unless (zerop z)
        (unless (zerop k)
          (next-sha3encode sha))
        (dotimes (i z)
          (setf (aref p k) (getc-sha3encode a i))
          (incf k 1)))))
  p)

(defun calc-sha3encode (sha &optional a)
  (result-sha3encode sha (sha3encode-dbyte sha) a))

(defun make-sha3encode (c d tail)
  (let ((r (- 1600 c)))
    (empty-sha3encode
      :rbyte (truncate r 8)
      :dbyte (truncate d 8)
      :tail tail)))

(defun make-sha3-224-encode ()
  (make-sha3encode 448 224 'sha3encode-01))

(defun make-sha3-256-encode ()
  (make-sha3encode 512 256 'sha3encode-01))

(defun make-sha3-384-encode ()
  (make-sha3encode 768 384 'sha3encode-01))

(defun make-sha3-512-encode ()
  (make-sha3encode 1024 512 'sha3encode-01))

(defun make-shake-128-encode ()
  (make-sha3encode 256 128 'sha3encode-1111))

(defun make-shake-256-encode ()
  (make-sha3encode 512 256 'sha3encode-1111))

(defun init-sha3encode (sha)
  (let ((array-a (sha3encode-a sha)))
    (dotimes (i 25)
      (setf (aref array-a i) 0)))
  (setf (sha3encode-index sha) 0)
  (values))

