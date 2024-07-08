(defpackage #:aes
  (:use #:common-lisp)
  (:export
    ;;  AES
    #:aes
    #:make-aes128
    #:make-aes192
    #:make-aes256
    #:aes-key
    #:aes-state
    #:aes-bit
    #:aes-byte
    #:aes-setkey
    #:aes-cipher1
    #:aes-cipher2

    ;;  CCM
    #:aes-ccm
    #:aes-ccm-key
    #:aes-ccm-nonce
    #:aes-ccm-adata
    #:make-aes-ccm-128
    #:make-aes-ccm-192
    #:make-aes-ccm-256
    #:aes-ccm-setkey
    #:aes-ccm-set-n
    #:aes-ccm-set-l
    #:aes-ccm-set-m
    #:aes-ccm-encrypt
    ))
(in-package #:aes)

(defconstant +aes-size+ 16)
(defconstant +aes-key+ 32)
(defconstant +aes-nb+ 4)
(defconstant +aes-word+ (* +aes-nb+ 15))

(defun make-vector8 (n)
  (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun make-vector32 (n)
  (make-array n :element-type '(unsigned-byte 32) :initial-element 0))

(defstruct aes
  (key (make-vector8 +aes-key+))
  (state (make-vector8 +aes-size+))
  (word (make-vector32 +aes-word+))
  nk nr bit byte)

(defun init-parameter-aes (a bit nk nr)
  (unless a
    (setq a (make-aes)))
  (setf (aes-bit a) bit
        (aes-byte a) (truncate bit 8)
        (aes-nk a) nk
        (aes-nr a) nr)
  a)

(defun init-aes128 (a)
  (init-parameter-aes a 128 4 10))

(defun init-aes192 (a)
  (init-parameter-aes a 192 6 12))

(defun init-aes256 (a)
  (init-parameter-aes a 256 8 14))

(defun make-aes128 ()
  (init-aes128 nil))

(defun make-aes192 ()
  (init-aes192 nil))

(defun make-aes256 ()
  (init-aes256 nil))


;;
;;  sub-bytes
;;
(defmacro defconstant-sub-bytes (name &rest args)
  `(defconstant ,name
     (make-array '(16 16) :initial-contents
                 ',(mapcar
                     (lambda (str &aux list)
                       (loop for i from 0 below (length str) by 2
                             do (push (parse-integer
                                        (subseq str i (+ i 2)) :radix 16) list))
                       (nreverse list))
                     args))))

(defconstant-sub-bytes
  +sub-bytes1+
  "637c777bf26b6fc53001672bfed7ab76" "ca82c97dfa5947f0add4a2af9ca472c0"
  "b7fd9326363ff7cc34a5e5f171d83115" "04c723c31896059a071280e2eb27b275"
  "09832c1a1b6e5aa0523bd6b329e32f84" "53d100ed20fcb15b6acbbe394a4c58cf"
  "d0efaafb434d338545f9027f503c9fa8" "51a3408f929d38f5bcb6da2110fff3d2"
  "cd0c13ec5f974417c4a77e3d645d1973" "60814fdc222a908846eeb814de5e0bdb"
  "e0323a0a4906245cc2d3ac629195e479" "e7c8376d8dd54ea96c56f4ea657aae08"
  "ba78252e1ca6b4c6e8dd741f4bbd8b8a" "703eb5664803f60e613557b986c11d9e"
  "e1f8981169d98e949b1e87e9ce5528df" "8ca1890dbfe6426841992d0fb054bb16")

(defconstant-sub-bytes
  +sub-bytes2+
  "52096ad53036a538bf40a39e81f3d7fb" "7ce339829b2fff87348e4344c4dee9cb"
  "547b9432a6c2233dee4c950b42fac34e" "082ea16628d924b2765ba2496d8bd125"
  "72f8f66486689816d4a45ccc5d65b692" "6c704850fdedb9da5e154657a78d9d84"
  "90d8ab008cbcd30af7e45805b8b34506" "d02c1e8fca3f0f02c1afbd0301138a6b"
  "3a9111414f67dcea97f2cfcef0b4e673" "96ac7422e7ad3585e2f937e81c75df6e"
  "47f11a711d29c5896fb7620eaa18be1b" "fc563e4bc6d279209adbc0fe78cd5af4"
  "1fdda8338807c731b11210592780ec5f" "60517fa919b54a0d2de57a9f93c99cef"
  "a0e03b4dae2af5b0c8ebbb3c83539961" "172b047eba77d626e169146355210c7d")

(defmacro get-state (state x y)
  `(aref ,state (+ (* 4 ,y) ,x)))

(defun sub-bytes-get (table v)
  (aref table (ash v -4) (logand v #x0F)))

(defun sub-bytes (a table)
  (let ((state (aes-state a)))
    (dotimes (y 4)
      (dotimes (x 4)
        (let ((v (get-state state x y)))
          (setf (get-state state x y) (sub-bytes-get table v)))))))

(defun sub-bytes1 (a)
  (sub-bytes a +sub-bytes1+))

(defun sub-bytes2 (a)
  (sub-bytes a +sub-bytes2+))


;;
;;  shift-rows
;;
(defun shift-rows1 (a)
  (let ((state (aes-state a)))
    ;;  1
    (rotatef
      (get-state state 1 0)
      (get-state state 1 1)
      (get-state state 1 2)
      (get-state state 1 3))

    ;;  2
    (let ((x (get-state state 2 0))
          (y (get-state state 2 1)))
      (setf (get-state state 2 0) (get-state state 2 2))
      (setf (get-state state 2 1) (get-state state 2 3))
      (setf (get-state state 2 2) x)
      (setf (get-state state 2 3) y))

    ;;  3
    (rotatef
      (get-state state 3 3)
      (get-state state 3 2)
      (get-state state 3 1)
      (get-state state 3 0))))

(defun shift-rows2 (a)
  (let ((state (aes-state a)))
    ;;  1
    (rotatef
      (get-state state 3 0)
      (get-state state 3 1)
      (get-state state 3 2)
      (get-state state 3 3))

    ;;  2
    (let ((x (get-state state 2 0))
          (y (get-state state 2 1)))
      (setf (get-state state 2 0) (get-state state 2 2))
      (setf (get-state state 2 1) (get-state state 2 3))
      (setf (get-state state 2 2) x)
      (setf (get-state state 2 3) y))

    ;;  3
    (rotatef
      (get-state state 1 3)
      (get-state state 1 2)
      (get-state state 1 1)
      (get-state state 1 0))))


;;
;;  mix-columns
;;
(defun xtime (x)
  (if (logbitp 7 x)
    (logand #xFF (logxor (ash x 1) #x1B))
    (logand #xFF (ash x 1))))

(defun mul-x02 (x)
  (xtime x))

(defun mul-x03 (x)
  (logxor x (xtime x)))

(defun mix-columns1 (a)
  (let ((state (aes-state a)))
    (dotimes (y 4)
      (let ((r1 (get-state state 0 y))
            (r2 (get-state state 1 y))
            (r3 (get-state state 2 y))
            (r4 (get-state state 3 y)))
        (setf (get-state state 0 y) (logxor (mul-x02 r1) (mul-x03 r2) r3 r4))
        (setf (get-state state 1 y) (logxor r1 (mul-x02 r2) (mul-x03 r3) r4))
        (setf (get-state state 2 y) (logxor r1 r2 (mul-x02 r3) (mul-x03 r4)))
        (setf (get-state state 3 y) (logxor (mul-x03 r1) r2 r3 (mul-x02 r4)))))))

(defun mul-x0e (x &aux y z)
  ;;  1110
  (setq x (xtime x))
  (setq y (xtime x))
  (setq z (xtime y))
  (logxor x y z))

(defun mul-x0b (x &aux y z)
  ;;  1011
  (setq y (xtime x))
  (setq z (xtime y))
  (setq z (xtime z))
  (logxor x y z))

(defun mul-x0d (x &aux y z)
  ;;  1101
  (setq y (xtime x))
  (setq y (xtime y))
  (setq z (xtime y))
  (logxor x y z))

(defun mul-x09 (x &aux y)
  ;;  1001
  (setq y (xtime x))
  (setq y (xtime y))
  (setq y (xtime y))
  (logxor x y))

(defun symb (&rest args)
  (intern (apply #'concatenate 'string (mapcar #'princ-to-string args))))

(defmacro mix-mul (a b c d r1 r2 r3 r4)
  `(logxor (,(symb 'mul- a) ,r1)
           (,(symb 'mul- b) ,r2)
           (,(symb 'mul- c) ,r3)
           (,(symb 'mul- d) ,r4)))

(defun mix-columns2 (a)
  (let ((state (aes-state a)))
    (dotimes (y 4)
      (let ((r1 (get-state state 0 y))
            (r2 (get-state state 1 y))
            (r3 (get-state state 2 y))
            (r4 (get-state state 3 y)))
        (setf (get-state state 0 y) (mix-mul x0e x0b x0d x09  r1 r2 r3 r4))
        (setf (get-state state 1 y) (mix-mul x09 x0e x0b x0d  r1 r2 r3 r4))
        (setf (get-state state 2 y) (mix-mul x0d x09 x0e x0b  r1 r2 r3 r4))
        (setf (get-state state 3 y) (mix-mul x0b x0d x09 x0e  r1 r2 r3 r4))))))


;;
;;  add-round-key
;;
(defun add-round-key (a index)
  (let ((state (aes-state a))
        (word (aes-word a))
        (index (* +aes-nb+ index)))
    (dotimes (y 4)
      (let ((v (aref word (+ index y)))
            (a (get-state state 0 y))
            (b (get-state state 1 y))
            (c (get-state state 2 y))
            (d (get-state state 3 y)))
        (setf (get-state state 0 y) (logxor a (logand #xFF (ash v -24))))
        (setf (get-state state 1 y) (logxor b (logand #xFF (ash v -16))))
        (setf (get-state state 2 y) (logxor c (logand #xFF (ash v -8))))
        (setf (get-state state 3 y) (logxor d (logand #xFF v)))))))


;;
;;  key
;;
(defconstant +aes-rcon+
  #(#x00000000 #x01000000 #x02000000 #x04000000
    #x08000000 #x10000000 #x20000000 #x40000000
    #x80000000 #x1B000000 #x36000000))

(defun make-word (a b c d)
  (logior (ash a 24) (ash b 16) (ash c 8) d))

(defun make-word-setkey (key i4)
  (make-word
    (aref key (+ i4 0))
    (aref key (+ i4 1))
    (aref key (+ i4 2))
    (aref key (+ i4 3))))

(defun sub-word (x)
  (make-word
    (sub-bytes-get +sub-bytes1+ (logand #xFF (ash x -24)))
    (sub-bytes-get +sub-bytes1+ (logand #xFF (ash x -16)))
    (sub-bytes-get +sub-bytes1+ (logand #xFF (ash x -8)))
    (sub-bytes-get +sub-bytes1+ (logand #xFF x))))

(defun rot-word (x)
  (make-word
    (logand #xFF (ash x -16))
    (logand #xFF (ash x -8))
    (logand #xFF x)
    (logand #xFF (ash x -24))))

(defun aes-setkey-word (a)
  (let ((key (aes-key a))
        (word (aes-word a)))
    (dotimes (i (aes-nk a))
      (setf (aref word i) (make-word-setkey key (* i 4))))))

(defun aes-setkey-update (word i nk)
  (let ((x (aref word (1- i)))
        (mod-ink (mod i nk)))
    (cond ((zerop mod-ink)
           (let ((y (sub-word (rot-word x)))
                 (z (aref +aes-rcon+ (truncate i nk))))
             (setq x (logxor y z))))
          ((and (> nk 6) (= mod-ink 4))
           (setq x (sub-word x))))
    (setf (aref word i) (logxor (aref word (- i nk)) x))))

(defun aes-setkey-loop (a)
  (let ((nk (aes-nk a))
        (word (aes-word a))
        (nbnk1 (* +aes-nb+ (1+ (aes-nr a)))))
    (loop for i from nk below nbnk1
          do (aes-setkey-update word i nk))))

(defun aes-setkey (a)
  (aes-setkey-word a)
  (aes-setkey-loop a))


;;
;;  cipher
;;
(defun aes-cipher1 (a)
  (let ((nr (aes-nr a)))
    (add-round-key a 0)
    (loop for round from 1 below nr
          do
          (sub-bytes1 a)
          (shift-rows1 a)
          (mix-columns1 a)
          (add-round-key a round))
    (sub-bytes1 a)
    (shift-rows1 a)
    (add-round-key a nr)))

(defun aes-cipher2 (a)
  (let ((nr (aes-nr a)))
    (add-round-key a nr)
    (loop for round downfrom (1- nr) above 0
          do
          (shift-rows2 a)
          (sub-bytes2 a)
          (add-round-key a round)
          (mix-columns2 a))
    (shift-rows2 a)
    (sub-bytes2 a)
    (add-round-key a 0)))


;;
;;  endian
;;
(defun integer-big-vector (v size)
  (let ((a (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (i size)
      (let ((k (- size i 1)))
        (setf (aref a i) (ldb (byte 8 (* k 8)) v))))
    a))

(defun setf-integer-big-vector (a v &key (start 0) end)
  (unless end
    (setq end (length a)))
  (let ((size (- end start)))
    (dotimes (i size)
      (let ((x (+ start i))
            (y (- size i 1)))
        (setf (aref a x) (ldb (byte 8 (* y 8)) v))))))


;;
;;  CCM
;;
(defstruct aes-ccm
  (aes1 (make-aes128))
  (aes2 (make-aes128))
  (key (make-vector8 32))
  (nonce (make-vector8 13))
  (copy (make-vector8 16))
  (first (make-vector8 16))
  (size-m 8 :type (member 4 6 8 10 12 14 16))
  (size-l 7 :type (integer 2 8))
  (size-n 8 :type (integer 7 13))
  (counter 0 :type unsigned-byte)
  (adata nil))

(defun make-aes-ccm-128 ()
  (let* ((ccm (make-aes-ccm))
         (aes1 (aes-ccm-aes1 ccm))
         (aes2 (aes-ccm-aes2 ccm)))
    (init-aes128 aes1)
    (init-aes128 aes2)
    ccm))

(defun make-aes-ccm-192 ()
  (let* ((ccm (make-aes-ccm))
         (aes1 (aes-ccm-aes1 ccm))
         (aes2 (aes-ccm-aes2 ccm)))
    (init-aes192 aes1)
    (init-aes192 aes2)
    ccm))

(defun make-aes-ccm-256 ()
  (let* ((ccm (make-aes-ccm))
         (aes1 (aes-ccm-aes1 ccm))
         (aes2 (aes-ccm-aes2 ccm)))
    (init-aes256 aes1)
    (init-aes256 aes2)
    ccm))

(defun aes-ccm-setkey (ccm)
  (let* ((aes1 (aes-ccm-aes1 ccm))
         (aes2 (aes-ccm-aes2 ccm))
         (key0 (aes-ccm-key ccm))
         (key1 (aes-key aes1))
         (key2 (aes-key aes2)))
    (setf (subseq key1 0 32) key0)
    (setf (subseq key2 0 32) key0)
    (aes-setkey aes1)
    (aes-setkey aes2)))

(defun aes-ccm-set-n (ccm size-n)
  (declare (type (integer 7 13) size-n))
  (setf (aes-ccm-size-l ccm) (- 15 size-n))
  (setf (aes-ccm-size-n ccm) size-n))

(defun aes-ccm-set-l (ccm size-l)
  (declare (type (integer 2 8) size-l))
  (setf (aes-ccm-size-n ccm) (- 15 size-l))
  (setf (aes-ccm-size-l ccm) size-l))

(defun aes-ccm-set-m (ccm size-m)
  (declare (type (member 4 6 8 10 12 14 16) size-m))
  (setf (aes-ccm-size-m ccm) size-m))

;;  mac
(defun aes-ccm-mac-flags (ccm)
  (let* ((adata (aes-ccm-adata ccm))
         (size-m (aes-ccm-size-m ccm))
         (size-l (aes-ccm-size-l ccm))
         (a (if (zerop (length adata)) 0 1))
         (m (/ (- size-m 2) 2))
         (l (1- size-l)))
    (+ (* 64 a) (* 8 m) l)))

(defun aes-ccm-mac-first (ccm input)
  (let* ((aes1 (aes-ccm-aes1 ccm))
         (state (aes-state aes1))
         (size-l (aes-ccm-size-l ccm))
         (x (- 16 size-l))
         (lm (length input)))
    (setf (aref state 0) (aes-ccm-mac-flags ccm))
    (setf (subseq state 1 x) (aes-ccm-nonce ccm))
    (setf-integer-big-vector state lm :start x :end 16)
    (aes-cipher1 aes1)))

(defun aes-ccm-state-xor (state x data y size)
  (dotimes (i size)
    (let ((k1 (+ x i))
          (k2 (+ y i)))
      (setf (aref state k1) (logxor (aref state k1) (aref data k2))))))

(defun aes-ccm-aes-xor (aes x data y size)
  (aes-ccm-state-xor (aes-state aes) x data y size))

(defun aes-ccm-mac-commit (aes1 x data y size)
  (aes-ccm-aes-xor aes1 x data y size)
  (aes-cipher1 aes1))

(defun aes-ccm-mac-send-commit (aes1 message base n m)
  (let ((x (+ base (* n 16))))
    (aes-ccm-mac-commit aes1 0 message x m)))

(defun aes-ccm-mac-send (aes1 message base size)
  (multiple-value-bind (n m) (truncate size 16)
    (dotimes (i n)
      (aes-ccm-mac-send-commit aes1 message base i 16))
    (unless (zerop m)
      (aes-ccm-mac-send-commit aes1 message base n m))))

(defun aes-ccm-mac-adata-header (size-a)
  (cond ((< size-a #.(- (ash 1 16) (ash 1 8)))
         (integer-big-vector size-a 2))
        ((< #.(ash 1 32))
         (setq size-a (+ #xFFFE00000000 size-a))
         (integer-big-vector size-a 6))
        ((< #.(ash 1 64))
         (setq size-a (+ #xFFFF0000000000000000 size-a))
         (integer-big-vector size-a 10))
        (t (error "Size ~A is too large." size-a))))

(defun aes-ccm-mac-adata-send (aes1 adata)
  (let* ((size-a (length adata))
         (header (aes-ccm-mac-adata-header size-a))
         (size-h (length header))
         (space (- 16 size-h)))
    (aes-ccm-aes-xor aes1 0 header 0 size-h)
    (if (< space size-a)
      (progn
        (aes-ccm-mac-commit aes1 size-h adata 0 space)
        (aes-ccm-mac-send aes1 adata space (- size-a space)))
      (aes-ccm-mac-commit aes1 size-h adata 0 size-a))))

(defun aes-ccm-mac-adata (ccm)
  (let ((adata (aes-ccm-adata ccm)))
    (unless (zerop (length adata))
      (aes-ccm-mac-adata-send
        (aes-ccm-aes1 ccm)
        adata))))

;;  cipher
(defun aes-ccm-cipher-copy (ccm)
  (let* ((state (make-vector8 16))
         (size-l (aes-ccm-size-l ccm))
         (x (- 16 size-l)))
    (setf (aref state 0) (1- (aes-ccm-size-l ccm)))
    (setf (subseq state 1 x) (aes-ccm-nonce ccm))
    (setf (aes-ccm-copy ccm) state)))

(defun aes-ccm-cipher-update (ccm)
  (let* ((counter (aes-ccm-counter ccm))
         (aes2 (aes-ccm-aes2 ccm))
         (state (aes-state aes2))
         (x (- 16 (aes-ccm-size-l ccm))))
    (setf (subseq state 0 16) (aes-ccm-copy ccm))
    (setf-integer-big-vector state counter :start x :end 16)
    (aes-cipher1 aes2)
    (incf (aes-ccm-counter ccm) 1)))

(defun aes-ccm-cipher-first (ccm)
  (aes-ccm-cipher-update ccm)
  (let* ((aes2 (aes-ccm-aes2 ccm))
         (state (aes-state aes2))
         (first (aes-ccm-first ccm)))
    (setf (subseq first 0 16) state)))

(defun aes-ccm-cipher-send1 (ccm input n m)
  (let ((aes1 (aes-ccm-aes1 ccm)))
    (aes-ccm-mac-send-commit aes1 input 0 n m)))

(defun aes-ccm-cipher-send2 (ccm input i size output)
  (let* ((x (* i 16))
         (y (+ x size))
         (aes2 (aes-ccm-aes2 ccm))
         (state (aes-state aes2)))
    (aes-ccm-cipher-update ccm)
    (aes-ccm-state-xor state 0 input x size)
    (setf (subseq output x y) (subseq state 0 size))))

(defun aes-ccm-cipher-loop (ccm input output)
  (let ((size (length input)))
    (multiple-value-bind (n m) (truncate size 16)
      (dotimes (i n)
        (aes-ccm-cipher-send1 ccm input i 16)
        (aes-ccm-cipher-send2 ccm input i 16 output))
      (unless (zerop m)
        (aes-ccm-cipher-send1 ccm input n m)
        (aes-ccm-cipher-send2 ccm input n m output)))))

;;  encrypt
(defun aes-ccm-encrypt-tag (ccm)
  (let* ((first (aes-ccm-first ccm))
         (aes1 (aes-ccm-aes1 ccm))
         (state (aes-state aes1))
         (size (aes-ccm-size-m ccm))
         (tag (make-vector8 size)))
    (dotimes (i size)
      (setf (aref tag i) (logxor (aref first i) (aref state i))))
    tag))

(defun aes-ccm-encrypt (ccm input &optional output)
  (unless output
    (setq output (make-vector8 (length input))))
  (aes-ccm-mac-first ccm input)
  (aes-ccm-mac-adata ccm)
  (aes-ccm-cipher-copy ccm)
  (aes-ccm-cipher-first ccm)
  (aes-ccm-cipher-loop ccm input output)
  (values output (aes-ccm-encrypt-tag ccm)))


;;
;;  GCM
;;
(defconstant +aes-gcm-multiple-r+ (ash #xE1 120))

(defun aes-gcm-multiple (x y)
  (let ((z 0) (v y))
    (dotimes (i 128)
      ;;  z
      (when (logbitp (- 127 i) x)
        (setq z (logxor z v)))
      ;;  v
      (setq v (ash v -1))
      (when (logbitp 0 v)
        (setq v (logxor v +aes-gcm-multiple-r+))))
    z))
