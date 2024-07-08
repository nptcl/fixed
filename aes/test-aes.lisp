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

(defmacro deftest-aes128-ccm (name const)
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


;;  1
(defconstant test-aes-ccm-128.1
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

(deftest-aes128-ccm aes-ccm-128.1 test-aes-ccm-128.1)


;;  2
(defconstant test-aes-ccm-128.2
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

(deftest-aes128-ccm aes-ccm-138.2 test-aes-ccm-128.2)


;;  2
(defconstant test-aes-ccm-128.3
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

(deftest-aes128-ccm aes-ccm-128.3 test-aes-ccm-128.3)


;;
;;  do-tests
;;
(do-tests)

