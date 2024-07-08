(defpackage #:chacha20
  (:use #:common-lisp)
  (:export
    #:chacha20
    #:make-chacha20
    #:chacha20-set-key
    #:chacha20-set-nonce
    #:chacha20-block
    #:chacha20-lambda
    #:chacha20-encrypt
    #:poly1305-ahead-encrypt
    #:poly1305-ahead-decrypt
    ))
(in-package #:chacha20)

(defun make-vector32 (n)
  (make-array n :element-type '(unsigned-byte 32)))

(defun make-vector8 (n)
  (make-array n :element-type '(unsigned-byte 8)))

(defstruct chacha20
  (state (make-vector32 16))
  (key (make-vector32 8))
  (nonce (make-vector32 3))
  (counter 1 :type (unsigned-byte 32)))


;;
;;  set-key
;;
(defun chacha20-vector-lambda (v &optional default)
  (let ((index 0)
        (size (length v)))
    (lambda ()
      (if (< index size)
        (prog1 (aref v index)
          (incf index 1))
        default))))

(defun chacha20-set-array (vector call size)
  (dotimes (x (truncate size 4))
    (let ((v 0))
      (dotimes (y 4)
        (setq v (logior v (ash (funcall call) (* y 8)))))
      (setf (aref vector x) v))))

(defun chacha20-set-key (c v)
  (chacha20-set-array
    (chacha20-key c)
    (chacha20-vector-lambda v 0)
    32))


;;
;;  set-nonce
;;
(defun chacha20-set-nonce (c v)
  (chacha20-set-array
    (chacha20-nonce c)
    (chacha20-vector-lambda v 0)
    12))


;;
;;  block
;;
(defconstant +header-chacha20+ #(#x61707865 #x3320646e #x79622d32 #x6b206574))

(defun logand32 (x)
  (logand #xFFFFFFFF x))

(defun p32 (&rest args)
  (logand32 (apply #'+ args)))

(defun chacha20-one-round (state a b d n)
  (setf (aref state a) (p32 (aref state a) (aref state b)))
  (setf (aref state d) (logxor (aref state d) (aref state a)))
  (let* ((v (aref state d))
         (x (logand32 (ash v n)))
         (y (ash v (- n 32))))
    (setf (aref state d) (logior x y))))

(defun chacha20-quater-round (state a b c d)
  (chacha20-one-round state a b d 16)
  (chacha20-one-round state c d b 12)
  (chacha20-one-round state a b d 8)
  (chacha20-one-round state c d b 7))

(defun chacha20-round (state)
  (dotimes (i 10)
    (chacha20-quater-round state 0 4 8 12)
    (chacha20-quater-round state 1 5 9 13)
    (chacha20-quater-round state 2 6 10 14)
    (chacha20-quater-round state 3 7 11 15)
    (chacha20-quater-round state 0 5 10 15)
    (chacha20-quater-round state 1 6 11 12)
    (chacha20-quater-round state 2 7 8 13)
    (chacha20-quater-round state 3 4 9 14)))

(defun chacha20-block (c)
  (let ((state (chacha20-state c))
        (init (make-vector32 16)))
    ;;  copy
    (setf (subseq init 0 4) +header-chacha20+)
    (setf (subseq init 4 12) (chacha20-key c))
    (setf (aref init 12) (chacha20-counter c))
    (setf (subseq init 13 16) (chacha20-nonce c))
    ;;  round
    (setf (subseq state 0 16) init)
    (chacha20-round init)
    ;;  add
    (dotimes (i 16)
      (setf (aref state i) (p32 (aref state i) (aref init i))))
    ;;  counter
    (setf (chacha20-counter c) (p32 (chacha20-counter c) 1))))

(defun chacha20-input-lambda (c)
  (let ((index 0)
        (state (chacha20-state c)))
    (chacha20-block c)
    (lambda ()
      (prog1
        (multiple-value-bind (n m) (truncate index 4)
          (logand #xFF (ash (aref state n) (* -8 m))))
        (incf index 1)
        (unless (< index 64)
          (chacha20-block c)
          (setq index 0))))))

(defun chacha20-lambda (c)
  (let* ((call (chacha20-input-lambda c)))
    (lambda (x)
      (logxor x (funcall call)))))

(defun chacha20-encrypt (c input)
  (map 'vector (chacha20-lambda c) input))


;;
;;  poly1305
;;
(defconstant +poly1305-clamp+ #x0ffffffc0ffffffc0ffffffc0fffffff)
(defconstant +poly1305-prime+ (- (expt 2 130) 5))

(defun integer-little-vector (v size)
  (let ((a (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (i size)
      (setf (aref a i) (ldb (byte 8 (* i 8)) v)))
    a))

(defun vector-little-integer (v &key (start 0) end)
  (unless end
    (setq end (length v)))
  (let ((r 0) (k 0))
    (loop for i from start below end
          do
          (setq r (logior r (ash (aref v i) (* k 8))))
          (incf k 1))
    r))

(defun poly1305-mac-input (r a msg i len)
  (let* ((x (* i 16))
         (y (+ x len))
         (n (vector-little-integer msg :start x :end y)))
    (setq n (logior n (ash 1 (* 8 len))))
    (mod (* r (+ a n)) +poly1305-prime+)))

(defun poly1305-mac (msg key)
  (let* ((r0 (vector-little-integer key :end 16))
         (r (logand +poly1305-clamp+ r0))
         (s (vector-little-integer key :start 16))
         (a 0))
    (multiple-value-bind (size tail) (truncate (length msg) 16)
      (dotimes (i size)
        (setq a (poly1305-mac-input r a msg i 16)))
      (unless (zerop tail)
        (setq a (poly1305-mac-input r a msg size tail))))
    (incf a s)
    (integer-little-vector a 16)))

(defun poly1305-key (c key nonce)
  (chacha20-set-key c key)
  (chacha20-set-nonce c nonce)
  (setf (chacha20-counter c) 0)
  (let ((call (chacha20-lambda c))
        (a (make-vector8 32)))
    (dotimes (i 32)
      (setf (aref a i) (funcall call #x00)))
    a))

(defun poly1306-ahead-pad16 (x)
  (let ((len16 (mod (length x) 16))
        (zero16 #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)))
    (if (zerop len16)
      #()
      (subseq zero16 0 (- 16 len16)))))

(defun poly1305-ahead-body (aad cipher)
  (concatenate
    'vector
    aad (poly1306-ahead-pad16 aad)
    cipher (poly1306-ahead-pad16 cipher)
    (integer-little-vector (length aad) 8)
    (integer-little-vector (length cipher) 8)))

(defun poly1305-ahead-encrypt (aad key nonce input)
  (let ((c (make-chacha20)))
    (let* ((otk (poly1305-key c key nonce))
           (cipher (chacha20-encrypt c input))
           (body (poly1305-ahead-body aad cipher))
           (tag (poly1305-mac body otk)))
      (values cipher tag))))

(defun poly1305-ahead-decrypt (aad key nonce cipher)
  (let ((c (make-chacha20)))
    (let* ((otk (poly1305-key c key nonce))
           (input (chacha20-encrypt c cipher))
           (body (poly1305-ahead-body aad cipher))
           (tag (poly1305-mac body otk)))
      (values input tag))))

