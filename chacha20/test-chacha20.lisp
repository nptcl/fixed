(defpackage work (:use common-lisp conc-rt chacha20))
(in-package work)

;;
;;  chacha20-encrypt
;;
(defun test-chacha20-encrypt-key (c)
  (let ((a (make-array 32)))
    (dotimes (i 32)
      (setf (aref a i) i))
    (chacha20-set-key c a)))

(defun test-chacha20-encrypt-nonce (c)
  (let ((nonce #(#x00 #x00 #x00 #x00 #x00 #x00 #x00 #x4a #x00 #x00 #x00 #x00)))
    (chacha20-set-nonce c nonce)))

(defun test-chacha20-encrypt-message ()
  (let ((s1 "Ladies and Gentlemen of the class of '99: ")
        (s2 "If I could offer you only one tip for the future, ")
        (s3 "sunscreen would be it."))
    (map 'vector #'char-code
         (concatenate 'string s1 s2 s3))))

(deftest chacha20-encrypt.1
  (let ((c (make-chacha20 ))
        (message (test-chacha20-encrypt-message)))
    (test-chacha20-encrypt-key c)
    (test-chacha20-encrypt-nonce c)
    (chacha20-encrypt c message))
  #(#x6e #x2e #x35 #x9a #x25 #x68 #xf9 #x80 #x41 #xba #x07 #x28 #xdd #x0d #x69 #x81
    #xe9 #x7e #x7a #xec #x1d #x43 #x60 #xc2 #x0a #x27 #xaf #xcc #xfd #x9f #xae #x0b
    #xf9 #x1b #x65 #xc5 #x52 #x47 #x33 #xab #x8f #x59 #x3d #xab #xcd #x62 #xb3 #x57
    #x16 #x39 #xd6 #x24 #xe6 #x51 #x52 #xab #x8f #x53 #x0c #x35 #x9f #x08 #x61 #xd8
    #x07 #xca #x0d #xbf #x50 #x0d #x6a #x61 #x56 #xa3 #x8e #x08 #x8a #x22 #xb6 #x5e
    #x52 #xbc #x51 #x4d #x16 #xcc #xf8 #x06 #x81 #x8c #xe9 #x1a #xb7 #x79 #x37 #x36
    #x5a #xf9 #x0b #xbf #x74 #xa3 #x5b #xe6 #xb4 #x0b #x8e #xed #xf2 #x78 #x5e #x42
    #x87 #x4d))


;;
;;  poly1305-mac
;;
(defconstant +test-poly1305-mac-key+
  #(#x85 #xd6 #xbe #x78 #x57 #x55 #x6d #x33
    #x7f #x44 #x52 #xfe #x42 #xd5 #x06 #xa8
    #x01 #x03 #x80 #x8a #xfb #x0d #xb2 #xfd
    #x4a #xbf #xf6 #xaf #x41 #x49 #xf5 #x1b))

(defconstant +test-poly1305-mac-msg+
  (map 'vector #'char-code "Cryptographic Forum Research Group"))

(defconstant +test-poly1305-mac-tag+
  #(#xa8 #x06 #x1d #xc1 #x30 #x51 #x36 #xc6
    #xc2 #x2b #x8b #xaf #x0c #x01 #x27 #xa9))

(deftest poly1305-mac.1
  (chacha20::poly1305-mac
    +test-poly1305-mac-msg+
    +test-poly1305-mac-key+)
  #.+test-poly1305-mac-tag+)


;;
;;  poly1305-key
;;
(defconstant +test-poly1305-key-key+
  #(#x80 #x81 #x82 #x83 #x84 #x85 #x86 #x87
    #x88 #x89 #x8a #x8b #x8c #x8d #x8e #x8f
    #x90 #x91 #x92 #x93 #x94 #x95 #x96 #x97
    #x98 #x99 #x9a #x9b #x9c #x9d #x9e #x9f))

(defconstant +test-poly1305-key-nonce+
  #(#x00 #x00 #x00 #x00 #x00 #x01 #x02 #x03 #x04 #x05 #x06 #x07))

(defconstant +test-poly1305-key-result+
  #(#x8a #xd5 #xa0 #x8b #x90 #x5f #x81 #xcc
    #x81 #x50 #x40 #x27 #x4a #xb2 #x94 #x71
    #xa8 #x33 #xb6 #x37 #xe3 #xfd #x0d #xa5
    #x08 #xdb #xb8 #xe2 #xfd #xd1 #xa6 #x46))

(deftest poly1305-key.1
  (let ((c (make-chacha20 :counter 0))
        (key +test-poly1305-key-key+)
        (nonce +test-poly1305-key-nonce+))
    (chacha20::poly1305-key c key nonce))
  #.+test-poly1305-key-result+)


;;
;;  poly1305-ahead-encrypt
;;
(defconstant +test-poly1305-ahead-encrypt-aad+
  #(#x50 #x51 #x52 #x53 #xc0 #xc1 #xc2 #xc3 #xc4 #xc5 #xc6 #xc7))

(defconstant +test-poly1305-ahead-encrypt-nonce+
  #(#x07 #x00 #x00 #x00  ;;  constant
    #x40 #x41 #x42 #x43 #x44 #x45 #x46 #x47  ;; iv
    ))

(defconstant +test-poly1305-ahead-encrypt-values1+
  #(#xd3 #x1a #x8d #x34 #x64 #x8e #x60 #xdb #x7b #x86 #xaf #xbc #x53 #xef #x7e #xc2
    #xa4 #xad #xed #x51 #x29 #x6e #x08 #xfe #xa9 #xe2 #xb5 #xa7 #x36 #xee #x62 #xd6
    #x3d #xbe #xa4 #x5e #x8c #xa9 #x67 #x12 #x82 #xfa #xfb #x69 #xda #x92 #x72 #x8b
    #x1a #x71 #xde #x0a #x9e #x06 #x0b #x29 #x05 #xd6 #xa5 #xb6 #x7e #xcd #x3b #x36
    #x92 #xdd #xbd #x7f #x2d #x77 #x8b #x8c #x98 #x03 #xae #xe3 #x28 #x09 #x1b #x58
    #xfa #xb3 #x24 #xe4 #xfa #xd6 #x75 #x94 #x55 #x85 #x80 #x8b #x48 #x31 #xd7 #xbc
    #x3f #xf4 #xde #xf0 #x8e #x4b #x7a #x9d #xe5 #x76 #xd2 #x65 #x86 #xce #xc6 #x4b
    #x61 #x16))

(defconstant +test-poly1305-ahead-encrypt-values2+
  #(#x1a #xe1 #x0b #x59 #x4f #x09 #xe2 #x6a #x7e #x90 #x2e #xcb #xd0 #x60 #x06 #x91))

(deftest poly1305-ahead-encrypt.1
  (let ((aad +test-poly1305-ahead-encrypt-aad+)
        (key +test-poly1305-key-key+)
        (nonce +test-poly1305-ahead-encrypt-nonce+)
        (input (test-chacha20-encrypt-message)))
    (poly1305-ahead-encrypt aad key nonce input))
  #.+test-poly1305-ahead-encrypt-values1+
  #.+test-poly1305-ahead-encrypt-values2+)

(deftest poly1305-ahead-encrypt.2
  (let ((aad +test-poly1305-ahead-encrypt-aad+)
        (key +test-poly1305-key-key+)
        (nonce +test-poly1305-ahead-encrypt-nonce+)
        (cipher +test-poly1305-ahead-encrypt-values1+))
    (poly1305-ahead-decrypt aad key nonce cipher))
  #.(test-chacha20-encrypt-message)
  #.+test-poly1305-ahead-encrypt-values2+)


;;
;;  do-tests
;;
(do-tests)

