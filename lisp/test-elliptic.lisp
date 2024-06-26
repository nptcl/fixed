(in-package elliptic)
(use-package 'conc-rt)

(defmacro with-elliptic-values (&body body)
  `(values
     (with-elliptic-secp256k1 ,@body)
     (with-elliptic-secp256r1 ,@body)
     (with-elliptic-ed25519 ,@body)
     (with-elliptic-ed448 ,@body)))


;;
;;  valid
;;
(deftest valid.1
  (with-elliptic-values
    (valid *elliptic-o*))
  nil nil t t)

(deftest valid.2
  (with-elliptic-values
    (valid *elliptic-g*))
  t t t t)


;;
;;  neutral
;;
(deftest neutral-weierstrass.1
  (with-elliptic-secp256k1
    (neutral (make-point2 0 0)))
  t)

(deftest neutral-weierstrass.2
  (with-elliptic-secp256k1
    (neutral (make-point2 1 0)))
  nil)

(deftest neutral-weierstrass.3
  (with-elliptic-secp256k1
    (neutral (make-point3 0 0 0)))
  t)

(deftest neutral-weierstrass.4
  (with-elliptic-secp256k1
    (neutral (make-point3 0 0 1)))
  nil)

(deftest neutral-weierstrass.5
  (with-elliptic-secp256k1
    (neutral (make-point4 0 0 0 0)))
  nil)

(deftest neutral-edwards.1
  (with-elliptic-ed25519
    (neutral (make-point2 0 0)))
  nil)

(deftest neutral-edwards.2
  (with-elliptic-ed25519
    (neutral (make-point2 0 1)))
  t)

(deftest neutral-edwards.3
  (with-elliptic-ed25519
    (neutral (make-point3 0 1)))
  t)

(deftest neutral-edwards.4
  (with-elliptic-ed25519
    (neutral (make-point3 0 2 2)))
  t)

(deftest neutral-edwards.5
  (with-elliptic-ed25519
    (neutral (make-point3 0 2)))
  nil)

(deftest neutral-edwards.6
  (with-elliptic-ed25519
    (neutral (make-point3 0 1 2)))
  nil)

(deftest neutral-edwards.7
  (with-elliptic-ed448
    (neutral (make-point4 0 1)))
  t)

(deftest neutral-edwards.8
  (with-elliptic-ed448
    (neutral (make-point4 0 2 2 0)))
  t)

(deftest neutral-edwards.9
  (with-elliptic-ed448
    (neutral (make-point4 0 2)))
  nil)

(deftest neutral-edwards.10
  (with-elliptic-ed448
    (neutral (make-point4 0 1 2)))
  nil)


;;
;;  inverse
;;
(defun inverse-test ()
  (let* ((x (random *elliptic-p*))
         (y (inverse x))
         (z (inverse y)))
    (= x z)))

(deftest inverse.1
  (with-elliptic-values
    (and (inverse-test)
         (inverse-test)
         (inverse-test)))
  t t t t)


;;
;;  square-root
;;
(defun square-root-test ()
  (let* ((x (random *elliptic-p*))
         (y (modp (- *elliptic-p* x)))
         (a (mulp x x))
         (z (if (eq *elliptic-curve* :ed25519)
              (square-root-mod-8 a)
              (square-root-mod-4 a))))
    (or (= x z) (= y z))))

(deftest square-root.1
  (with-elliptic-values
    (and (square-root-test)
         (square-root-test)
         (square-root-test)))
  t t t t)

(defun square-root-test-lastbit (n)
  (let* ((x (dpb n (byte 1 0) (random *elliptic-p*)))
         (a (mulp x x))
         (z (if (eq *elliptic-curve* :ed25519)
              (square-root-mod-8 a)
              (square-root-mod-4 a))))
    (when (/= (logand z #x01) n)
      (setq z (- *elliptic-p* z)))
    (= x z)))

(deftest square-root.2
  (with-elliptic-values
    (and (square-root-test-lastbit 0)
         (square-root-test-lastbit 0)
         (square-root-test-lastbit 0)))
  t t t t)

(deftest square-root.3
  (with-elliptic-values
    (and (square-root-test-lastbit 1)
         (square-root-test-lastbit 1)
         (square-root-test-lastbit 1)))
  t t t t)


;;
;;  addition
;;

;;  addition O+G
(deftest addition.1
  (with-elliptic-values
    (let ((g *elliptic-g*)
          (o *elliptic-o*))
      (equal-point (addition g o) g)))
  t t t t)

;;  addition G+O
(deftest addition.2
  (with-elliptic-values
    (let ((g *elliptic-g*)
          (o *elliptic-o*))
      (equal-point (addition o g) g)))
  t t t t)

;;  addition O+O
(deftest addition.3
  (with-elliptic-values
    (let ((o *elliptic-o*))
      (equal-point (addition o o) o)))
  t t t t)

;;  doubling O
(deftest addition.4
  (with-elliptic-values
    (let ((o *elliptic-o*))
      (equal-point (doubling o) o)))
  t t t t)

(deftest addition.5
  (with-elliptic-values
    (let ((g *elliptic-g*)
          (o *elliptic-o*))
      (equal-point
        (addition (doubling o) g)
        g)))
  t t t t)

(deftest addition.6
  (with-elliptic-values
    (let ((g *elliptic-g*)
          (o *elliptic-o*))
      (equal-point
        (addition g (doubling o))
        g)))
  t t t t)

;;  addition G+G
(deftest addition.7
  (with-elliptic-values
    (let ((g *elliptic-g*))
      (valid (addition g g))))
  t t t t)

;;  doubling G
(deftest addition.8
  (with-elliptic-values
    (let ((g *elliptic-g*))
      (valid (doubling g))))
  t t t t)

;;  multiple 2G
(deftest addition.9
  (with-elliptic-values
    (let ((g *elliptic-g*))
      (valid (multiple 2 g))))
  t t t t)

;;  2G
(deftest addition.10
  (with-elliptic-values
    (let* ((g *elliptic-g*)
           (x (addition g g))
           (y (doubling g))
           (z (multiple 2 g)))
      (and (equal-point x y)
           (equal-point x z))))
  t t t t)


;;
;;  doubling
;;
(deftest doubling.1
  (with-elliptic-secp256k1
    (let ((x (make-point3 1 0 0)))
      (neutral
        (doubling x))))
  t)

(deftest doubling.2
  (with-elliptic-secp256r1
    (let ((x (make-point3 1 0 0)))
      (neutral
        (doubling x))))
  t)


;;
;;  multiple
;;

;;  multiple 0G
(deftest multiple.1
  (with-elliptic-values
    (equal-point
      (multiple 0 *elliptic-g*)
      *elliptic-o*))
  t t t t)

;;  multiple 1G
(deftest multiple.2
  (with-elliptic-values
    (equal-point
      (multiple 1 *elliptic-g*)
      *elliptic-g*))
  t t t t)

;;  multiple 5G
(deftest multiple.3
  (with-elliptic-values
    (valid (multiple 5 *elliptic-g*)))
  t t t t)

(deftest multiple.4
  (with-elliptic-values
    (let ((g *elliptic-g*))
      (equal-point
        (multiple 5 *elliptic-g*)
        (addition
          (addition
            (addition
              (addition g g) g) g) g))))
  t t t t)

(deftest multiple.5
  (with-elliptic-values
    (let* ((g *elliptic-g*)
           (g2 (doubling g)))
      (equal-point
        (multiple 5 *elliptic-g*)
        (addition
          (addition g2 g2) g))))
  t t t t)

;;  multiple nG
(deftest multiple.6
  (with-elliptic-values
    (let* ((g *elliptic-g*)
           (ng (multiple *elliptic-n* g)))
      (neutral ng)))
  t t t t)

(deftest multiple.7
  (with-elliptic-values
    (let* ((g *elliptic-g*)
           (ng (multiple *elliptic-n* g)))
      (equal-point
        (addition g ng)
        g)))
  t t t t)

(deftest multiple.8
  (with-elliptic-values
    (let* ((g *elliptic-g*)
           (ng (multiple *elliptic-n* g)))
      (equal-point
        (addition ng g)
        g)))
  t t t t)

(deftest multiple.9
  (with-elliptic-values
    (let* ((g *elliptic-g*)
           (x (multiple 1000 g))
           (y (multiple (- *elliptic-n* 1000) g)))
      (neutral
        (addition x y))))
  t t t t)


;;
;;  encode
;;
(defun encode-vector-string (r compress)
  (with-output-to-string (s)
    (let ((v (encode r compress)))
      (check-type v vector)
      (map nil (lambda (x) (format s "~2,'0X" x)) v))))

(defconstant +encode-secp256k1-x+
  "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
(defconstant +encode-secp256k1-y+
  "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")

(deftest encode-secp256k1.1
  (with-elliptic-secp256k1
    (vectorp (encode *elliptic-g*)))
  t)

(deftest encode-secp256k1.2
  (with-elliptic-secp256k1
    (encode-vector-string *elliptic-o* nil))
  "00")

(deftest encode-secp256k1.3
  (with-elliptic-secp256k1
    (encode-vector-string *elliptic-o* t))
  "00")

(deftest encode-secp256k1.4
  (with-elliptic-secp256k1
    (equalp
      (encode-vector-string *elliptic-g* nil)
      (concatenate 'string "04" +encode-secp256k1-x+ +encode-secp256k1-y+)))
  t)

(deftest encode-secp256k1.5
  (with-elliptic-secp256k1
    (equalp
      (encode-vector-string *elliptic-g* t)
      (concatenate 'string "02" +encode-secp256k1-x+)))
  t)

(defconstant +encode-secp256r1-x+
  "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")
(defconstant +encode-secp256r1-y+
  "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")

(deftest encode-secp256r1.1
  (with-elliptic-secp256r1
    (vectorp (encode *elliptic-g*)))
  t)

(deftest encode-secp256r1.2
  (with-elliptic-secp256r1
    (encode-vector-string *elliptic-o* nil))
  "00")

(deftest encode-secp256r1.3
  (with-elliptic-secp256r1
    (encode-vector-string *elliptic-o* t))
  "00")

(deftest encode-secp256r1.4
  (with-elliptic-secp256r1
    (equalp
      (encode-vector-string *elliptic-g* nil)
      (concatenate 'string "04" +encode-secp256r1-x+ +encode-secp256r1-y+)))
  t)

(deftest encode-secp256r1.5
  (with-elliptic-secp256r1
    (equalp
      (encode-vector-string *elliptic-g* t)
      (concatenate 'string "03" +encode-secp256r1-x+)))
  t)


;;  G  (x0=0)
;;    216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
;;    6666666666666666666666666666666666666666666666666666666666666658
;;  5G  (x0=1)
;;    49FDA73EADE3587BFCEF7CF7D12DA5DE5C2819F93E1BE1A591409CC0322EF233
;;    5F4825B298FEAE6FE02C6E148992466631282ECA89430B5D10D21F83D676C8ED
(deftest encode-ed25519.1
  (with-elliptic-ed25519
    (integerp (encode *elliptic-g*)))
  t)

(deftest encode-ed25519.2
  (with-elliptic-ed25519
    (encode *elliptic-g*))
  #x6666666666666666666666666666666666666666666666666666666666666658)

(deftest encode-ed25519.3
  (with-elliptic-ed25519
    (encode (multiple 5 *elliptic-g*)))
  #xDF4825B298FEAE6FE02C6E148992466631282ECA89430B5D10D21F83D676C8ED)


;;  G  (x0=0)
;;  79A70B2B70400553AE7C9DF416C792C61128751AC92969240C25A07D728BDC93E21F7787ED6972249DE732F38496CD11698713093E9C04FC
;;  7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80000000000000000000000000000000000000000000000000000001
;;  2G  (x0=1)
;;  BB72037BF55D1FD93AB61D862E22CF02C7C590349D3C67995D14F6F7E1E733F24A36F4A9575933A7DF92BD4966380E62A89F63CBA606444F
;;  289DED68857A5E30EBB712BCE84346051D99E5E7FCD7DCD2948F8EEEFFD75A0600968505A7A501AE3A811ABA3408956CE924A6860DAAFA37
(deftest encode-ed448.1
  (with-elliptic-ed448
    (integerp (encode *elliptic-g*)))
  t)

(deftest encode-ed448.2
  (with-elliptic-ed448
    (encode *elliptic-g*))
  #x007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80000000000000000000000000000000000000000000000000000001)

(deftest encode-ed448.3
  (with-elliptic-ed448
    (encode (multiple 2 *elliptic-g*)))
  #x80289DED68857A5E30EBB712BCE84346051D99E5E7FCD7DCD2948F8EEEFFD75A0600968505A7A501AE3A811ABA3408956CE924A6860DAAFA37)


;;
;;  decode
;;
(deftest decode-secp256k1.1
  (with-elliptic-secp256k1
    (let* ((g *elliptic-g*)
           (x (encode g t))
           (y (decode x)))
      (equal-point g y)))
  t)

(deftest decode-secp256k1.2
  (with-elliptic-secp256k1
    (let* ((g *elliptic-g*)
           (x (encode g nil))
           (y (decode x)))
      (equal-point g y)))
  t)

(deftest decode-secp256k1.3
  (with-elliptic-secp256k1
    (let* ((x (encode *elliptic-o* t))
           (y (decode x)))
      (neutral y)))
  t)

(deftest decode-secp256k1.4
  (with-elliptic-secp256k1
    (let* ((x (encode *elliptic-o* nil))
           (y (decode x)))
      (neutral y)))
  t)

(deftest decode-secp256r1.1
  (with-elliptic-secp256r1
    (let* ((g *elliptic-g*)
           (x (encode g t))
           (y (decode x)))
      (equal-point g y)))
  t)

(deftest decode-secp256r1.2
  (with-elliptic-secp256r1
    (let* ((g *elliptic-g*)
           (x (encode g nil))
           (y (decode x)))
      (equal-point g y)))
  t)

(deftest decode-secp256r1.3
  (with-elliptic-secp256r1
    (let* ((x (encode *elliptic-o* t))
           (y (decode x)))
      (neutral y)))
  t)

(deftest decode-secp256r1.4
  (with-elliptic-secp256r1
    (let* ((x (encode *elliptic-o* nil))
           (y (decode x)))
      (neutral y)))
  t)

(deftest decode-ed25519.1
  (with-elliptic-ed25519
    (let* ((x (encode *elliptic-o*))
           (y (decode x)))
      (neutral y)))
  t)

(deftest decode-ed25519.2
  (with-elliptic-ed25519
    (let* ((g *elliptic-g*)
           (x (encode g))
           (y (decode x)))
      (equal-point g y)))
  t)

(deftest decode-ed25519.3
  (with-elliptic-ed25519
    (let* ((g (multiple 5 *elliptic-g*))  ;; 5G
           (x (encode g))
           (y (decode x)))
      (equal-point g y)))
  t)

(deftest decode-ed448.1
  (with-elliptic-ed448
    (let* ((x (encode *elliptic-o*))
           (y (decode x)))
      (neutral y)))
  t)

(deftest decode-ed448.2
  (with-elliptic-ed448
    (let* ((g *elliptic-g*)
           (x (encode g))
           (y (decode x)))
      (equal-point g y)))
  t)

(deftest decode-ed448.3
  (with-elliptic-ed448
    (let* ((g (multiple 2 *elliptic-g*))  ;; 2G
           (x (encode g))
           (y (decode x)))
      (equal-point g y)))
  t)


;;
;;  make-private
;;
(deftest make-private.1
  (with-elliptic-values
    (integerp (make-private)))
  t t t t)


;;
;;  make-public
;;
(deftest make-public.1
  (with-elliptic-values
    (let ((s (make-private)))
      (typep (make-public s) 'point3)))  ;; include point4
  t t t t)

(deftest make-public-secp256k1.1
  (with-elliptic-secp256k1
    (equal-point
      (make-public 1)
      *elliptic-g*))
  t)

(deftest make-public-secp256r1.1
  (with-elliptic-secp256r1
    (equal-point
      (make-public 1)
      *elliptic-g*))
  t)

(defun split-2byte-rfc8032 (str)
  (let (list)
    (dotimes (i (/ (length str) 2))
      (let ((i2 (* i 2)))
        (push (subseq str i2 (+ i2 2)) list)))
    (nreverse list)))

(defun list-intger-rfc8032 (args)
  (mapcar
    (lambda (x)
      (parse-integer x :radix 16))
    (split-2byte-rfc8032
      (apply #'concatenate 'string args))))

(defun string-integer-rfc8032 (&rest args)
  (let ((r 0) (shift 0))
    (dolist (x (list-intger-rfc8032 args))
      (setq r (logior r (ash x shift)))
      (incf shift 8))
    r))

(defun public-rfc8032-ed25519 (s1 s2 p1 p2)
  (let ((s (string-integer-rfc8032 s1 s2))
        (p (string-integer-rfc8032 p1 p2)))
    (equal-point
      (make-public s)
      (decode p))))

(deftest make-public-ed25519.1
  (with-elliptic-ed25519
    (public-rfc8032-ed25519
      "9d61b19deffd5a60ba844af492ec2cc4"
      "4449c5697b326919703bac031cae7f60"
      "d75a980182b10ab7d54bfed3c964073a"
      "0ee172f3daa62325af021a68f707511a"))
  t)

(deftest make-public-ed25519.2
  (with-elliptic-ed25519
    (public-rfc8032-ed25519
      "4ccd089b28ff96da9db6c346ec114e0f"
      "5b8a319f35aba624da8cf6ed4fb8a6fb"
      "3d4017c3e843895a92b70aa74d1b7ebc"
      "9c982ccf2ec4968cc0cd55f12af4660c"))
  t)

(deftest make-public-ed25519.3
  (with-elliptic-ed25519
    (public-rfc8032-ed25519
      "c5aa8df43f9f837bedb7442f31dcb7b1"
      "66d38535076f094b85ce3a2e0b4458f7"
      "fc51cd8e6218a1a38da47ed00230f058"
      "0816ed13ba3303ac5deb911548908025"))
  t)

(deftest make-public-ed25519.4
  (with-elliptic-ed25519
    (public-rfc8032-ed25519
      "f5e5767cf153319517630f226876b86c"
      "8160cc583bc013744c6bf255f5cc0ee5"
      "278117fc144c72340f67d0f2316e8386"
      "ceffbf2b2428c9c51fef7c597f1d426e"))
  t)

(deftest make-public-ed25519.5
  (with-elliptic-ed25519
    (public-rfc8032-ed25519
      "833fe62409237b9d62ec77587520911e"
      "9a759cec1d19755b7da901b96dca3d42"
      "ec172b93ad5e563bf4932c70e1245034"
      "c35467ef2efd4d64ebf819683467e2bf"))
  t)

#|
(defun public-rfc8032-ed448 (s1 s2 s3 s4 p1 p2 p3 p4)
  (let ((s (string-integer-rfc8032 s1 s2 s3 s4))
        (p (string-integer-rfc8032 p1 p2 p3 p4)))
    (equal-point
      (make-public s)
      (decode p))))

(deftest make-public-ed448.1
  (with-elliptic-ed448
    (public-rfc8032-ed448
      "6c82a562cb808d10d632be89c8513ebf"
      "6c929f34ddfa8c9f63c9960ef6e348a3"
      "528c8a3fcc2f044e39a3fc5b94492f8f"
      "032e7549a20098f95b"
      "5fd7449b59b461fd2ce787ec616ad46a"
      "1da1342485a70e1f8a0ea75d80e96778"
      "edf124769b46c7061bd6783df1e50f6c"
      "d1fa1abeafe8256180"))
  t)
|#


;;
;;  main
;;
(let ((*random-state* (make-random-state t)))
  (do-tests))

