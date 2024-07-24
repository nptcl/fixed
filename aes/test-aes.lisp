(defpackage work (:use common-lisp conc-rt aes))
(in-package work)

(defun test-setarray (array str)
  (setf str (remove #\Space str))
  (let* ((size (length str))
         (size2 (truncate size 2)))
    (dotimes (i size2)
      (setf (aref array i)
            (parse-integer
              (subseq str (* i 2) (+ (* i 2) 2))
              :radix 16)))))

(defun test-setstate (a str)
  (test-setarray (aes-state a) str))

(defun test-setkey (a str)
  (test-setarray (aes-key a) str))

(defun test-getstate (a)
  (let ((state (aes-state a)))
    (string-downcase
      (with-output-to-string (s)
        (dotimes (i 16)
          (format s "~2,'0X" (aref state i)))))))

(defun test-genarray (&rest args)
  (let* ((x (apply #'concatenate 'string args))
         (y (remove #\Space x))
         (a (make-array (truncate (length y) 2))))
    (test-setarray a y)
    a))


;;
;;  word
;;
(deftest rot-word.1
  (aes::rot-word #x09cf4f3c)
  #xcf4f3c09)

(deftest sub-word.1
  (aes::sub-word #xcf4f3c09)
  #x8a84eb01)

(deftest key-expansion.1
  (let ((a (make-aes128)))
    (test-setkey a "2b7e151628aed2a6abf7158809cf4f3c")
    (aes-setkey a)
    (let ((word (aes::aes-word a)))
      (values
        (aref word 0) (aref word 1) (aref word 2) (aref word 3)
        (aref word 40) (aref word 41) (aref word 42) (aref word 43))))
  #x2b7e1516 #x28aed2a6 #xabf71588 #x09cf4f3c
  #xd014f9a8 #xc9ee2589 #xe13f0cc8 #xb6630ca6)



;;
;;  cipher1
;;
(deftest aes128-cipher1.1
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "00112233445566778899aabbccddeeff")
    (aes-setkey a)
    (aes::add-round-key a 0)
    (test-getstate a))
  "00102030405060708090a0b0c0d0e0f0")

(deftest aes128-cipher1.2
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "00102030405060708090a0b0c0d0e0f0")
    (aes-setkey a)
    (aes::sub-bytes1 a)
    (test-getstate a))
  "63cab7040953d051cd60e0e7ba70e18c")

(deftest aes128-cipher1.3
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "63cab7040953d051cd60e0e7ba70e18c")
    (aes-setkey a)
    (aes::shift-rows1 a)
    (test-getstate a))
  "6353e08c0960e104cd70b751bacad0e7")

(deftest aes128-cipher1.4
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "6353e08c0960e104cd70b751bacad0e7")
    (aes-setkey a)
    (aes::mix-columns1 a)
    (test-getstate a))
  "5f72641557f5bc92f7be3b291db9f91a")

(deftest aes128-cipher1.5
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "5f72641557f5bc92f7be3b291db9f91a")
    (aes-setkey a)
    (aes::add-round-key a 1)
    (test-getstate a))
  "89d810e8855ace682d1843d8cb128fe4")

(deftest aes128-cipher1.6
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "00112233445566778899aabbccddeeff")
    (aes-setkey a)
    (aes-cipher1 a)
    (test-getstate a))
  "69c4e0d86a7b0430d8cdb78070b4c55a")


;;
;;  cipher2
;;
(deftest aes128-cipher2.1
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "69c4e0d86a7b0430d8cdb78070b4c55a")
    (aes-setkey a)
    (aes::add-round-key a 10)
    (test-getstate a))
  "7ad5fda789ef4e272bca100b3d9ff59f")

(deftest aes128-cipher2.2
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "7ad5fda789ef4e272bca100b3d9ff59f")
    (aes-setkey a)
    (aes::shift-rows2 a)
    (test-getstate a))
  "7a9f102789d5f50b2beffd9f3dca4ea7")

(deftest aes128-cipher2.3
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "7a9f102789d5f50b2beffd9f3dca4ea7")
    (aes-setkey a)
    (aes::sub-bytes2 a)
    (test-getstate a))
  "bd6e7c3df2b5779e0b61216e8b10b689")

(deftest aes128-cipher2.4
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "bd6e7c3df2b5779e0b61216e8b10b689")
    (aes-setkey a)
    (aes::add-round-key a 9)
    (test-getstate a))
  "e9f74eec023020f61bf2ccf2353c21c7")

(deftest aes128-cipher2.5
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "e9f74eec023020f61bf2ccf2353c21c7")
    (aes-setkey a)
    (aes::mix-columns2 a)
    (test-getstate a))
  "54d990a16ba09ab596bbf40ea111702f")

(deftest aes128-cipher2.6
  (let ((a (make-aes128)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f")
    (test-setstate a "69c4e0d86a7b0430d8cdb78070b4c55a")
    (aes-setkey a)
    (aes-cipher2 a)
    (test-getstate a))
  "00112233445566778899aabbccddeeff")


;;
;;  aes192
;;
(deftest aes192-cipher1.1
  (let ((a (make-aes192)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f1011121314151617")
    (test-setstate a "00112233445566778899aabbccddeeff")
    (aes-setkey a)
    (aes-cipher1 a)
    (test-getstate a))
  "dda97ca4864cdfe06eaf70a0ec0d7191")

(deftest aes192-cipher2.1
  (let ((a (make-aes192)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f1011121314151617")
    (test-setstate a "dda97ca4864cdfe06eaf70a0ec0d7191")
    (aes-setkey a)
    (aes-cipher2 a)
    (test-getstate a))
  "00112233445566778899aabbccddeeff")


;;
;;  aes256
;;
(deftest aes256-cipher1.1
  (let ((a (make-aes256)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    (test-setstate a "00112233445566778899aabbccddeeff")
    (aes-setkey a)
    (aes-cipher1 a)
    (test-getstate a))
  "8ea2b7ca516745bfeafc49904b496089")

(deftest aes256-cipher2.1
  (let ((a (make-aes256)))
    (test-setkey a "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    (test-setstate a "8ea2b7ca516745bfeafc49904b496089")
    (aes-setkey a)
    (aes-cipher2 a)
    (test-getstate a))
  "00112233445566778899aabbccddeeff")


;;
;;  aes-ccm-128
;;
(defmacro defvector16 (name &rest args)
  `(defconstant ,name (test-genarray ,@args)))

(defmacro deftest-aes128-ccm-encrypt (name const)
  (let ((n (symbol-value const)))
    `(deftest ,name
       (let ((ccm (make-aes-ccm-128))
             (input ,(apply #'test-genarray (nth 3 n))))
         (aes-ccm-set-l ccm 2)
         (setf (aes-ccm-adata ccm) ,(apply #'test-genarray (nth 2 n)))
         (setf (aes-ccm-key ccm) ,(apply #'test-genarray (nth 0 n)))
         (setf (aes-ccm-nonce ccm) ,(apply #'test-genarray (nth 1 n)))
         (aes-ccm-setkey ccm)
         (aes-ccm-encrypt ccm input))
       ,(apply #'test-genarray (nth 4 n))
       ,(apply #'test-genarray (nth 5 n)))))

(defmacro deftest-aes128-ccm-decrypt (name const)
  (let ((n (symbol-value const)))
    `(deftest ,name
       (let ((ccm (make-aes-ccm-128))
             (input ,(apply #'test-genarray (nth 4 n))))
         (aes-ccm-set-l ccm 2)
         (setf (aes-ccm-adata ccm) ,(apply #'test-genarray (nth 2 n)))
         (setf (aes-ccm-key ccm) ,(apply #'test-genarray (nth 0 n)))
         (setf (aes-ccm-nonce ccm) ,(apply #'test-genarray (nth 1 n)))
         (aes-ccm-setkey ccm)
         (aes-ccm-decrypt ccm input))
       ,(apply #'test-genarray (nth 3 n))
       ,(apply #'test-genarray (nth 5 n)))))


;;  1
(defconstant aes128-ccm-test.1
  '(("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF")  ;; key
    ("00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5")  ;; nonce
    ("00 01 02 03  04 05 06 07")  ;; adata
    ("08 09 0A 0B  0C 0D 0E 0F"  ;; input
     "10 11 12 13  14 15 16 17"
     "18 19 1A 1B  1C 1D 1E")
    ("58 8C 97 9A  61 C6 63 D2"  ;; output
     "F0 66 D0 C2  C0 F9 89 80"
     "6D 5F 6B 61  DA C3 84")
    ("17 E8 D1 2C  FD F9 26 E0")))  ;; tag

(deftest-aes128-ccm-encrypt
  aes128-ccm-encrypt.1
  aes128-ccm-test.1)

(deftest-aes128-ccm-decrypt
  aes128-ccm-decrypt.1
  aes128-ccm-test.1)


;;  2
(defconstant aes128-ccm-test.2
  '(("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF")  ;; key
    ("00 00 00 04  03 02 01 A0  A1 A2 A3 A4  A5")  ;; nonce
    ("00 01 02 03  04 05 06 07")  ;; adata
    ("08 09 0A 0B  0C 0D 0E 0F"  ;; input
     "10 11 12 13  14 15 16 17"
     "18 19 1A 1B  1C 1D 1E 1F")
    ("72 C9 1A 36  E1 35 F8 CF"
     "29 1C A8 94  08 5C 87 E3"
     "CC 15 C4 39  C9 E4 3A 3B")
    ("A0 91 D5 6E  10 40 09 16")))

(deftest-aes128-ccm-encrypt
  aes128-ccm-encrypt.2
  aes128-ccm-test.2)

(deftest-aes128-ccm-decrypt
  aes128-ccm-decrypt.2
  aes128-ccm-test.2)


;;  3
(defconstant aes128-ccm-test.3
  '(("C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF")  ;; key
    ("00 00 00 05  04 03 02 A0  A1 A2 A3 A4  A5")
    ("00 01 02 03  04 05 06 07")  ;; adata
    ("08 09 0A 0B  0C 0D 0E 0F"  ;; input
     "10 11 12 13  14 15 16 17"
     "18 19 1A 1B  1C 1D 1E 1F"
     "20")
    ("51 B1 E5 F4  4A 19 7D 1D"
     "A4 6B 0F 8E  2D 28 2A E8"
     "71 E8 38 BB  64 DA 85 96"
     "57")
    ("4A DA A7 6F  BD 9F B0 C5")))

(deftest-aes128-ccm-encrypt
  aes128-ccm-encrypt.3
  aes128-ccm-test.3)

(deftest-aes128-ccm-decrypt
  aes128-ccm-decrypt.3
  aes128-ccm-test.3)


;;
;;  aes-gcm
;;
(deftest aes-gcm-counter.1
  (let ((g (make-aes-gcm-128)))
    (setf (aes::aes-gcm-y g) #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
    (aes::aes-gcm-counter-y g)
    (aes::aes-gcm-y g))
  #xFFFFFFFFFFFFFFFFFFFFFFFF00000000)

;;  1
(deftest aes-gcm-testcase-1.1
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "00000000000000000000000000000000"))
    (setf (aes-gcm-nonce g) (test-genarray "000000000000000000000000"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g #()))
  #()
  #.(test-genarray "58e2fccefa7e3061367f1d57a4e7455a"))

(deftest aes-gcm-testcase-1.2
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "00000000000000000000000000000000"))
    (setf (aes-gcm-nonce g) (test-genarray "000000000000000000000000"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g #()))
  #()
  #.(test-genarray "58e2fccefa7e3061367f1d57a4e7455a"))

;;  2
(deftest aes-gcm-testcase-2.1
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "00000000000000000000000000000000"))
    (setf (aes-gcm-nonce g) (test-genarray "000000000000000000000000"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g (test-genarray "00000000000000000000000000000000")))
  #.(test-genarray "0388dace60b6a392f328c2b971b2fe78")
  #.(test-genarray "ab6e47d42cec13bdf53a67b21257bddf"))

(deftest aes-gcm-testcase-2.2
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "00000000000000000000000000000000"))
    (setf (aes-gcm-nonce g) (test-genarray "000000000000000000000000"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g (test-genarray "0388dace60b6a392f328c2b971b2fe78")))
  #.(test-genarray "00000000000000000000000000000000")
  #.(test-genarray "ab6e47d42cec13bdf53a67b21257bddf"))

;;  3
(defparameter aes-gcm-testcase-3-input
  (test-genarray "d9313225f88406e5a55909c5aff5269a"
                 "86a7a9531534f7da2e4c303d8a318a72"
                 "1c3c0c95956809532fcf0e2449a6b525"
                 "b16aedf5aa0de657ba637b391aafd255"))

(defparameter aes-gcm-testcase-3-output
  (test-genarray "42831ec2217774244b7221b784d0d49c"
                 "e3aa212f2c02a4e035c17e2329aca12e"
                 "21d514b25466931c7d8f6a5aac84aa05"
                 "1ba30b396a0aac973d58e091473f5985"))

(deftest aes-gcm-testcase-3.1
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "feffe9928665731c6d6a8f9467308308"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbaddecaf888"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g aes-gcm-testcase-3-input))
  #.aes-gcm-testcase-3-output
  #.(test-genarray "4d5c2af327cd64a62cf35abd2ba6fab4"))

(deftest aes-gcm-testcase-3.2
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "feffe9928665731c6d6a8f9467308308"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbaddecaf888"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g aes-gcm-testcase-3-output))
  #.aes-gcm-testcase-3-input
  #.(test-genarray "4d5c2af327cd64a62cf35abd2ba6fab4"))

;;  4
(defparameter aes-gcm-testcase-4-input
  (test-genarray "d9313225f88406e5a55909c5aff5269a"
                 "86a7a9531534f7da2e4c303d8a318a72"
                 "1c3c0c95956809532fcf0e2449a6b525"
                 "b16aedf5aa0de657ba637b39"))

(defparameter aes-gcm-testcase-4-output
  (test-genarray "42831ec2217774244b7221b784d0d49c"
                 "e3aa212f2c02a4e035c17e2329aca12e"
                 "21d514b25466931c7d8f6a5aac84aa05"
                 "1ba30b396a0aac973d58e091"))

(deftest aes-gcm-testcase-4.1
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "feffe9928665731c6d6a8f9467308308"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbaddecaf888"))
    (setf (aes-gcm-adata g)
          (test-genarray "feedfacedeadbeeffeedfacedeadbeef" "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g aes-gcm-testcase-4-input))
  #.aes-gcm-testcase-4-output
  #.(test-genarray "5bc94fbc3221a5db94fae95ae7121a47"))

(deftest aes-gcm-testcase-4.2
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "feffe9928665731c6d6a8f9467308308"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbaddecaf888"))
    (setf (aes-gcm-adata g)
          (test-genarray "feedfacedeadbeeffeedfacedeadbeef" "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g aes-gcm-testcase-4-output))
  #.aes-gcm-testcase-4-input
  #.(test-genarray "5bc94fbc3221a5db94fae95ae7121a47"))

;;  5
(defparameter aes-gcm-testcase-5-input
  (test-genarray "d9313225f88406e5a55909c5aff5269a"
                 "86a7a9531534f7da2e4c303d8a318a72"
                 "1c3c0c95956809532fcf0e2449a6b525"
                 "b16aedf5aa0de657ba637b39"))

(defparameter aes-gcm-testcase-5-output
  (test-genarray "61353b4c2806934a777ff51fa22a4755"
                 "699b2a714fcdc6f83766e5f97b6c7423"
                 "73806900e49f24b22b097544d4896b42"
                 "4989b5e1ebac0f07c23f4598"))

(deftest aes-gcm-testcase-5.1
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "feffe9928665731c6d6a8f9467308308"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbad"))
    (setf (aes-gcm-adata g)
          (test-genarray "feedfacedeadbeeffeedfacedeadbeef" "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g aes-gcm-testcase-5-input))
  #.aes-gcm-testcase-5-output
  #.(test-genarray "3612d2e79e3b0785561be14aaca2fccb"))

(deftest aes-gcm-testcase-5.2
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "feffe9928665731c6d6a8f9467308308"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbad"))
    (setf (aes-gcm-adata g)
          (test-genarray "feedfacedeadbeeffeedfacedeadbeef" "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g aes-gcm-testcase-5-output))
  #.aes-gcm-testcase-5-input
  #.(test-genarray "3612d2e79e3b0785561be14aaca2fccb"))

;;  6
(defparameter aes-gcm-testcase-6-input
  (test-genarray "d9313225f88406e5a55909c5aff5269a"
                 "86a7a9531534f7da2e4c303d8a318a72"
                 "1c3c0c95956809532fcf0e2449a6b525"
                 "b16aedf5aa0de657ba637b39"))

(defparameter aes-gcm-testcase-6-output
  (test-genarray "8ce24998625615b603a033aca13fb894"
                 "be9112a5c3a211a8ba262a3cca7e2ca7"
                 "01e4a9a4fba43c90ccdcb281d48c7c6f"
                 "d62875d2aca417034c34aee5"))

(deftest aes-gcm-testcase-6.1
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "feffe9928665731c6d6a8f9467308308"))
    (setf (aes-gcm-nonce g)
          (test-genarray "9313225df88406e555909c5aff5269aa"
                         "6a7a9538534f7da1e4c303d2a318a728"
                         "c3c0c95156809539fcf0e2429a6b5254"
                         "16aedbf5a0de6a57a637b39b"))
    (setf (aes-gcm-adata g)
          (test-genarray "feedfacedeadbeeffeedfacedeadbeef" "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g aes-gcm-testcase-6-input))
  #.aes-gcm-testcase-6-output
  #.(test-genarray "619cc5aefffe0bfa462af43c1699d050"))

(deftest aes-gcm-testcase-6.2
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "feffe9928665731c6d6a8f9467308308"))
    (setf (aes-gcm-nonce g)
          (test-genarray "9313225df88406e555909c5aff5269aa"
                         "6a7a9538534f7da1e4c303d2a318a728"
                         "c3c0c95156809539fcf0e2429a6b5254"
                         "16aedbf5a0de6a57a637b39b"))
    (setf (aes-gcm-adata g)
          (test-genarray "feedfacedeadbeeffeedfacedeadbeef" "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g aes-gcm-testcase-6-output))
  #.aes-gcm-testcase-6-input
  #.(test-genarray "619cc5aefffe0bfa462af43c1699d050"))

;;  7
(deftest aes-gcm-testcase-7.1
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "00000000000000000000000000000000"
                                           "0000000000000000"))
    (setf (aes-gcm-nonce g) (test-genarray "000000000000000000000000"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g #()))
  #()
  #.(test-genarray "cd33b28ac773f74ba00ed1f312572435"))

(deftest aes-gcm-testcase-7.2
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "00000000000000000000000000000000"
                                           "0000000000000000"))
    (setf (aes-gcm-nonce g) (test-genarray "000000000000000000000000"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g #()))
  #()
  #.(test-genarray "cd33b28ac773f74ba00ed1f312572435"))

;;  8
(deftest aes-gcm-testcase-8.1
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "00000000000000000000000000000000"
                                           "0000000000000000"))
    (setf (aes-gcm-nonce g) (test-genarray "000000000000000000000000"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g (test-genarray "00000000000000000000000000000000")))
  #.(test-genarray "98e7247c07f0fe411c267e4384b0f600")
  #.(test-genarray "2ff58d80033927ab8ef4d4587514f0fb"))

(deftest aes-gcm-testcase-8.2
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "00000000000000000000000000000000"
                                           "0000000000000000"))
    (setf (aes-gcm-nonce g) (test-genarray "000000000000000000000000"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g (test-genarray "98e7247c07f0fe411c267e4384b0f600")))
  #.(test-genarray "00000000000000000000000000000000")
  #.(test-genarray "2ff58d80033927ab8ef4d4587514f0fb"))

;;  9
(defparameter aes-gcm-testcase-9-input
  (test-genarray "d9313225f88406e5a55909c5aff5269a"
                 "86a7a9531534f7da2e4c303d8a318a72"
                 "1c3c0c95956809532fcf0e2449a6b525"
                 "b16aedf5aa0de657ba637b391aafd255"))

(defparameter aes-gcm-testcase-9-output
  (test-genarray "3980ca0b3c00e841eb06fac4872a2757"
                 "859e1ceaa6efd984628593b40ca1e19c"
                 "7d773d00c144c525ac619d18c84a3f47"
                 "18e2448b2fe324d9ccda2710acade256"))

(deftest aes-gcm-testcase-9.1
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "feffe9928665731c6d6a8f9467308308"
                                           "feffe9928665731c"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbaddecaf888"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g aes-gcm-testcase-9-input))
  #.aes-gcm-testcase-9-output
  #.(test-genarray "9924a7c8587336bfb118024db8674a14"))

(deftest aes-gcm-testcase-9.2
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "feffe9928665731c6d6a8f9467308308"
                                           "feffe9928665731c"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbaddecaf888"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g aes-gcm-testcase-9-output))
  #.aes-gcm-testcase-9-input
  #.(test-genarray "9924a7c8587336bfb118024db8674a14"))

;;  10
(defparameter aes-gcm-testcase-10-input
  (test-genarray "d9313225f88406e5a55909c5aff5269a"
                 "86a7a9531534f7da2e4c303d8a318a72"
                 "1c3c0c95956809532fcf0e2449a6b525"
                 "b16aedf5aa0de657ba637b39"))

(defparameter aes-gcm-testcase-10-output
  (test-genarray "3980ca0b3c00e841eb06fac4872a2757"
                 "859e1ceaa6efd984628593b40ca1e19c"
                 "7d773d00c144c525ac619d18c84a3f47"
                 "18e2448b2fe324d9ccda2710"))

(deftest aes-gcm-testcase-10.1
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "feffe9928665731c6d6a8f9467308308"
                                           "feffe9928665731c"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbaddecaf888"))
    (setf (aes-gcm-adata g) (test-genarray "feedfacedeadbeeffeedfacedeadbeef"
                                           "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g aes-gcm-testcase-10-input))
  #.aes-gcm-testcase-10-output
  #.(test-genarray "2519498e80f1478f37ba55bd6d27618c"))

(deftest aes-gcm-testcase-10.2
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "feffe9928665731c6d6a8f9467308308"
                                           "feffe9928665731c"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbaddecaf888"))
    (setf (aes-gcm-adata g) (test-genarray "feedfacedeadbeeffeedfacedeadbeef"
                                           "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g aes-gcm-testcase-10-output))
  #.aes-gcm-testcase-10-input
  #.(test-genarray "2519498e80f1478f37ba55bd6d27618c"))

;;  11
(defparameter aes-gcm-testcase-11-input
  (test-genarray "d9313225f88406e5a55909c5aff5269a"
                 "86a7a9531534f7da2e4c303d8a318a72"
                 "1c3c0c95956809532fcf0e2449a6b525"
                 "b16aedf5aa0de657ba637b39"))

(defparameter aes-gcm-testcase-11-output
  (test-genarray "0f10f599ae14a154ed24b36e25324db8"
                 "c566632ef2bbb34f8347280fc4507057"
                 "fddc29df9a471f75c66541d4d4dad1c9"
                 "e93a19a58e8b473fa0f062f7"))

(deftest aes-gcm-testcase-11.1
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "feffe9928665731c6d6a8f9467308308"
                                           "feffe9928665731c"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbad"))
    (setf (aes-gcm-adata g) (test-genarray "feedfacedeadbeeffeedfacedeadbeef"
                                           "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g aes-gcm-testcase-11-input))
  #.aes-gcm-testcase-11-output
  #.(test-genarray "65dcc57fcf623a24094fcca40d3533f8"))

(deftest aes-gcm-testcase-11.2
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "feffe9928665731c6d6a8f9467308308"
                                           "feffe9928665731c"))
    (setf (aes-gcm-nonce g) (test-genarray "cafebabefacedbad"))
    (setf (aes-gcm-adata g) (test-genarray "feedfacedeadbeeffeedfacedeadbeef"
                                           "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g aes-gcm-testcase-11-output))
  #.aes-gcm-testcase-11-input
  #.(test-genarray "65dcc57fcf623a24094fcca40d3533f8"))

;;  12
(defparameter aes-gcm-testcase-12-input
  (test-genarray "d9313225f88406e5a55909c5aff5269a"
                 "86a7a9531534f7da2e4c303d8a318a72"
                 "1c3c0c95956809532fcf0e2449a6b525"
                 "b16aedf5aa0de657ba637b39"))

(defparameter aes-gcm-testcase-12-output
  (test-genarray "d27e88681ce3243c4830165a8fdcf9ff"
                 "1de9a1d8e6b447ef6ef7b79828666e45"
                 "81e79012af34ddd9e2f037589b292db3"
                 "e67c036745fa22e7e9b7373b"))

(deftest aes-gcm-testcase-12.1
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "feffe9928665731c6d6a8f9467308308"
                                           "feffe9928665731c"))
    (setf (aes-gcm-nonce g) (test-genarray "9313225df88406e555909c5aff5269aa"
                                           "6a7a9538534f7da1e4c303d2a318a728"
                                           "c3c0c95156809539fcf0e2429a6b5254"
                                           "16aedbf5a0de6a57a637b39b"))
    (setf (aes-gcm-adata g) (test-genarray "feedfacedeadbeeffeedfacedeadbeef"
                                           "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g aes-gcm-testcase-12-input))
  #.aes-gcm-testcase-12-output
  #.(test-genarray "dcf566ff291c25bbb8568fc3d376a6d9"))

(deftest aes-gcm-testcase-12.2
  (let* ((g (make-aes-gcm-192))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 24) (test-genarray "feffe9928665731c6d6a8f9467308308"
                                           "feffe9928665731c"))
    (setf (aes-gcm-nonce g) (test-genarray "9313225df88406e555909c5aff5269aa"
                                           "6a7a9538534f7da1e4c303d2a318a728"
                                           "c3c0c95156809539fcf0e2429a6b5254"
                                           "16aedbf5a0de6a57a637b39b"))
    (setf (aes-gcm-adata g) (test-genarray "feedfacedeadbeeffeedfacedeadbeef"
                                           "abaddad2"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g aes-gcm-testcase-12-output))
  #.aes-gcm-testcase-12-input
  #.(test-genarray "dcf566ff291c25bbb8568fc3d376a6d9"))


;;
;;  aes-gcm.pdf
;;
(deftest aes-gcm-128.1
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "FEFFE992 8665731C 6D6A8F94 67308308"))
    (setf (aes-gcm-nonce g) (test-genarray "CAFEBABE FACEDBAD DECAF888"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g #()))
  #()
  #.(test-genarray "3247184B 3C4F69A4 4DBCD228 87BBB418"))

(deftest aes-gcm-128.2
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "FEFFE992 8665731C 6D6A8F94 67308308"))
    (setf (aes-gcm-nonce g) (test-genarray "CAFEBABE FACEDBAD DECAF888"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g #()))
  #()
  #.(test-genarray "3247184B 3C4F69A4 4DBCD228 87BBB418"))

(deftest aes-gcm-128.3
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "FEFFE992 8665731C 6D6A8F94 67308308"))
    (setf (aes-gcm-nonce g) (test-genarray "CAFEBABE FACEDBAD DECAF888"))
    (aes-gcm-setkey g)
    (aes-gcm-encrypt g (test-genarray
                         "D9313225 F88406E5 A55909C5 AFF5269A"
                         "86A7A953 1534F7DA 2E4C303D 8A318A72"
                         "1C3C0C95 95680953 2FCF0E24 49A6B525"
                         "B16AEDF5 AA0DE657 BA637B39 1AAFD255")))
  #.(test-genarray
      "42831EC2 21777424 4B7221B7 84D0D49C"
      "E3AA212F 2C02A4E0 35C17E23 29ACA12E"
      "21D514B2 5466931C 7D8F6A5A AC84AA05"
      "1BA30B39 6A0AAC97 3D58E091 473F5985")
  #.(test-genarray "4D5C2AF3 27CD64A6 2CF35ABD 2BA6FAB4"))

(deftest aes-gcm-128.4
  (let* ((g (make-aes-gcm-128))
         (key (aes-gcm-key g)))
    (setf (subseq key 0 16) (test-genarray "FEFFE992 8665731C 6D6A8F94 67308308"))
    (setf (aes-gcm-nonce g) (test-genarray "CAFEBABE FACEDBAD DECAF888"))
    (aes-gcm-setkey g)
    (aes-gcm-decrypt g (test-genarray
                         "42831EC2 21777424 4B7221B7 84D0D49C"
                         "E3AA212F 2C02A4E0 35C17E23 29ACA12E"
                         "21D514B2 5466931C 7D8F6A5A AC84AA05"
                         "1BA30B39 6A0AAC97 3D58E091 473F5985")))
  #.(test-genarray "D9313225 F88406E5 A55909C5 AFF5269A"
                   "86A7A953 1534F7DA 2E4C303D 8A318A72"
                   "1C3C0C95 95680953 2FCF0E24 49A6B525"
                   "B16AEDF5 AA0DE657 BA637B39 1AAFD255")
  #.(test-genarray "4D5C2AF3 27CD64A6 2CF35ABD 2BA6FAB4"))


;;
;;  do-tests
;;
(let ((*print-pretty* nil)
      (*print-base* 16))
  (do-tests))

