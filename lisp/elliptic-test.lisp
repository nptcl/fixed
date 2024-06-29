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
      (equal-point (addition o g) g)))
  t t t t)

;;  addition G+O
(deftest addition.2
  (with-elliptic-values
    (let ((g *elliptic-g*)
          (o *elliptic-o*))
      (equal-point (addition g o) g)))
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
;;  4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E
;;  693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14

;;  2G  (x0=2)
;;  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA955555555555555555555555555555555555555555555555555555555
;;  AE05E9634AD7048DB359D6205086C2B0036ED7A035884DD7B7E36D728AD8C4B80D6565833A2A3098BBBCB2BED1CDA06BDAEAFBCDEA9386ED
(deftest encode-ed448.1
  (with-elliptic-ed448
    (integerp (encode *elliptic-g*)))
  t)

(deftest encode-ed448.2
  (with-elliptic-ed448
    (encode *elliptic-g*))
  #x00693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14)

(deftest encode-ed448.3
  (with-elliptic-ed448
    (encode (multiple 2 *elliptic-g*)))
  #x80AE05E9634AD7048DB359D6205086C2B0036ED7A035884DD7B7E36D728AD8C4B80D6565833A2A3098BBBCB2BED1CDA06BDAEAFBCDEA9386ED)


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

(deftest make-public-ed448.2
  (with-elliptic-ed448
    (public-rfc8032-ed448
      "c4eab05d357007c632f3dbb48489924d"
      "552b08fe0c353a0d4a1f00acda2c463a"
      "fbea67c5e8d2877c5e3bc397a659949e"
      "f8021e954e0a12274e"
      "43ba28f430cdff456ae531545f7ecd0a"
      "c834a55d9358c0372bfa0c6c6798c086"
      "6aea01eb00742802b8438ea4cb82169c"
      "235160627b4c3a9480"))
  t)

(deftest make-public-ed448.3
  (with-elliptic-ed448
    (public-rfc8032-ed448
      "c4eab05d357007c632f3dbb48489924d"
      "552b08fe0c353a0d4a1f00acda2c463a"
      "fbea67c5e8d2877c5e3bc397a659949e"
      "f8021e954e0a12274e"
      "43ba28f430cdff456ae531545f7ecd0a"
      "c834a55d9358c0372bfa0c6c6798c086"
      "6aea01eb00742802b8438ea4cb82169c"
      "235160627b4c3a9480"))
  t)

(deftest make-public-ed448.4
  (with-elliptic-ed448
    (public-rfc8032-ed448
      "cd23d24f714274e744343237b93290f5"
      "11f6425f98e64459ff203e8985083ffd"
      "f60500553abc0e05cd02184bdb89c4cc"
      "d67e187951267eb328"
      "dcea9e78f35a1bf3499a831b10b86c90"
      "aac01cd84b67a0109b55a36e9328b1e3"
      "65fce161d71ce7131a543ea4cb5f7e9f"
      "1d8b00696447001400"))
  t)

(deftest make-public-ed448.5
  (with-elliptic-ed448
    (public-rfc8032-ed448
      "258cdd4ada32ed9c9ff54e63756ae582"
      "fb8fab2ac721f2c8e676a72768513d93"
      "9f63dddb55609133f29adf86ec9929dc"
      "cb52c1c5fd2ff7e21b"
      "3ba16da0c6f2cc1f30187740756f5e79"
      "8d6bc5fc015d7c63cc9510ee3fd44adc"
      "24d8e968b6e46e6f94d19b945361726b"
      "d75e149ef09817f580"))
  t)


;;
;;  sign
;;
(deftest sign.1
  (with-elliptic-values
    (let* ((private (make-private))
           (public (make-public private))
           (m1 (map 'vector #'char-code "Hello"))
           (m2 (map 'vector #'char-code "Hello")))
      (multiple-value-bind (r s) (sign private m1)
        (verify public m2 r s))))
  t t t t)

(deftest sign.2
  (with-elliptic-values
    (let* ((private (make-private))
           (public (make-public private))
           (m1 (map 'vector #'char-code "Hello"))
           (m2 (map 'vector #'char-code "Hallo")))
      (multiple-value-bind (r s) (sign private m1)
        (verify public m2 r s))))
  nil nil nil nil)

(deftest sign.3
  (with-elliptic-values
    (let* ((private (make-private))
           (public (make-public (mod (1+ private) *elliptic-p*)))
           (m1 (map 'vector #'char-code "Hello"))
           (m2 (map 'vector #'char-code "Hello")))
      (multiple-value-bind (r s) (sign private m1)
        (verify public m2 r s))))
  nil nil nil nil)

(defun sign-rfc8032 (p1 p2 r1 r2 s1 s2 &rest args)
  (let ((p (string-integer-rfc8032 p1 p2))
        (r (string-integer-rfc8032 r1 r2))
        (s (string-integer-rfc8032 s1 s2))
        (m (list-intger-rfc8032 args)))
    (multiple-value-bind (x y) (sign p m)
      (and (= r x)
           (= s y)))))

(deftest sign-rfc8032-ed25519.1
  (with-elliptic-ed25519
    (sign-rfc8032
      "9d61b19deffd5a60ba844af492ec2cc4"
      "4449c5697b326919703bac031cae7f60"
      "e5564300c360ac729086e2cc806e828a"
      "84877f1eb8e5d974d873e06522490155"
      "5fb8821590a33bacc61e39701cf9b46b"
      "d25bf5f0595bbe24655141438e7a100b"))
  t)

(deftest sign-rfc8032-ed25519.2
  (with-elliptic-ed25519
    (sign-rfc8032
      "4ccd089b28ff96da9db6c346ec114e0f"
      "5b8a319f35aba624da8cf6ed4fb8a6fb"
      "92a009a9f0d4cab8720e820b5f642540"
      "a2b27b5416503f8fb3762223ebdb69da"
      "085ac1e43e15996e458f3613d0f11d8c"
      "387b2eaeb4302aeeb00d291612bb0c00"
      "72"))
  t)

(deftest sign-rfc8032-ed25519.3
  (with-elliptic-ed25519
    (sign-rfc8032
      "c5aa8df43f9f837bedb7442f31dcb7b1"
      "66d38535076f094b85ce3a2e0b4458f7"
      "6291d657deec24024827e69c3abe01a3"
      "0ce548a284743a445e3680d7db5ac3ac"
      "18ff9b538d16f290ae67f760984dc659"
      "4a7c15e9716ed28dc027beceea1ec40a"
      "af82"))
  t)

(deftest sign-rfc8032-ed25519.4
  (with-elliptic-ed25519
    (sign-rfc8032
      "f5e5767cf153319517630f226876b86c"
      "8160cc583bc013744c6bf255f5cc0ee5"
      "0aab4c900501b3e24d7cdf4663326a3a"
      "87df5e4843b2cbdb67cbf6e460fec350"
      "aa5371b1508f9f4528ecea23c436d94b"
      "5e8fcd4f681e30a6ac00a9704a188a03"
      "08b8b2b733424243760fe426a4b54908"
      "632110a66c2f6591eabd3345e3e4eb98"
      "fa6e264bf09efe12ee50f8f54e9f77b1"
      "e355f6c50544e23fb1433ddf73be84d8"
      "79de7c0046dc4996d9e773f4bc9efe57"
      "38829adb26c81b37c93a1b270b20329d"
      "658675fc6ea534e0810a4432826bf58c"
      "941efb65d57a338bbd2e26640f89ffbc"
      "1a858efcb8550ee3a5e1998bd177e93a"
      "7363c344fe6b199ee5d02e82d522c4fe"
      "ba15452f80288a821a579116ec6dad2b"
      "3b310da903401aa62100ab5d1a36553e"
      "06203b33890cc9b832f79ef80560ccb9"
      "a39ce767967ed628c6ad573cb116dbef"
      "efd75499da96bd68a8a97b928a8bbc10"
      "3b6621fcde2beca1231d206be6cd9ec7"
      "aff6f6c94fcd7204ed3455c68c83f4a4"
      "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
      "85ce81bd84359d44254d95629e9855a9"
      "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
      "d17ba70eb6248e594e1a2297acbbb39d"
      "502f1a8c6eb6f1ce22b3de1a1f40cc24"
      "554119a831a9aad6079cad88425de6bd"
      "e1a9187ebb6092cf67bf2b13fd65f270"
      "88d78b7e883c8759d2c4f5c65adb7553"
      "878ad575f9fad878e80a0c9ba63bcbcc"
      "2732e69485bbc9c90bfbd62481d9089b"
      "eccf80cfe2df16a2cf65bd92dd597b07"
      "07e0917af48bbb75fed413d238f5555a"
      "7a569d80c3414a8d0859dc65a46128ba"
      "b27af87a71314f318c782b23ebfe808b"
      "82b0ce26401d2e22f04d83d1255dc51a"
      "ddd3b75a2b1ae0784504df543af8969b"
      "e3ea7082ff7fc9888c144da2af58429e"
      "c96031dbcad3dad9af0dcbaaaf268cb8"
      "fcffead94f3c7ca495e056a9b47acdb7"
      "51fb73e666c6c655ade8297297d07ad1"
      "ba5e43f1bca32301651339e22904cc8c"
      "42f58c30c04aafdb038dda0847dd988d"
      "cda6f3bfd15c4b4c4525004aa06eeff8"
      "ca61783aacec57fb3d1f92b0fe2fd1a8"
      "5f6724517b65e614ad6808d6f6ee34df"
      "f7310fdc82aebfd904b01e1dc54b2927"
      "094b2db68d6f903b68401adebf5a7e08"
      "d78ff4ef5d63653a65040cf9bfd4aca7"
      "984a74d37145986780fc0b16ac451649"
      "de6188a7dbdf191f64b5fc5e2ab47b57"
      "f7f7276cd419c17a3ca8e1b939ae49e4"
      "88acba6b965610b5480109c8b17b80e1"
      "b7b750dfc7598d5d5011fd2dcc5600a3"
      "2ef5b52a1ecc820e308aa342721aac09"
      "43bf6686b64b2579376504ccc493d97e"
      "6aed3fb0f9cd71a43dd497f01f17c0e2"
      "cb3797aa2a2f256656168e6c496afc5f"
      "b93246f6b1116398a346f1a641f3b041"
      "e989f7914f90cc2c7fff357876e506b5"
      "0d334ba77c225bc307ba537152f3f161"
      "0e4eafe595f6d9d90d11faa933a15ef1"
      "369546868a7f3a45a96768d40fd9d034"
      "12c091c6315cf4fde7cb68606937380d"
      "b2eaaa707b4c4185c32eddcdd306705e"
      "4dc1ffc872eeee475a64dfac86aba41c"
      "0618983f8741c5ef68d3a101e8a3b8ca"
      "c60c905c15fc910840b94c00a0b9d0"))
  t)

(deftest sign-rfc8032-ed448.1
  (with-elliptic-ed448
    (sign-rfc8032
      "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3"
      "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
      "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f"
      "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980"
      "ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda"
      "8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"))
  t)

(deftest sign-rfc8032-ed448.2
  (with-elliptic-ed448
    (sign-rfc8032
      "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a"
      "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
      "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435"
      "2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd77980"
      "5e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905"
      "e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"
      "03"))
  t)

(deftest sign-rfc8032-ed448.3
  (with-elliptic-ed448
    (let ((*elliptic-context* #(#x66 #x6f #x6f)))
      (sign-rfc8032
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a"
        "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
        "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2"
        "151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea00"
        "0c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f57"
        "8c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00"
        "03")))
  t)


;;
;;  encode-string
;;
(deftest encode1-vector.1
  (with-elliptic-secp256k1
    (values
      (length (encode1-vector 0))
      (length (encode1-string 0))))
  32 64)

(deftest encode1-vector.2
  (with-elliptic-secp256r1
    (values
      (length (encode1-vector 0))
      (length (encode1-string 0))))
  32 64)

(deftest encode1-vector.3
  (with-elliptic-ed25519
    (values
      (length (encode1-vector 0))
      (length (encode1-string 0))))
  32 64)

(deftest encode1-vector.4
  (with-elliptic-ed448
    (values
      (length (encode1-vector 0))
      (length (encode1-string 0))))
  57 114)

(defun encode-decode-private (private1)
  (with-elliptic-values
    (let* ((public1 (make-public private1))
           (private2 (decode1-vector (encode1-vector private1)))
           (public2 (decode2-vector (encode2-vector public1))))
      (and (= private1 private2)
           (equal-point public1 public2)))))

(deftest encode-decode.1
  (encode-decode-private #x00)
  t t t t)

(deftest encode-decode.2
  (encode-decode-private #x01)
  t t t t)

(deftest encode-decode.3
  (encode-decode-private #x12345678)
  t t t t)

(defun encode-check-private (private)
  (let ((public (make-public private)))
    (values (encode1-string private)
            (encode2-string public))))

(deftest encode-check.1
  (with-elliptic-secp256k1
    (encode-check-private #x00))
  "0000000000000000000000000000000000000000000000000000000000000000"
  "00")

(deftest encode-check.2
  (with-elliptic-secp256r1
    (encode-check-private #x00))
  "0000000000000000000000000000000000000000000000000000000000000000"
  "00")

(deftest encode-check.3
  (with-elliptic-ed25519
    (encode-check-private #x00))
  "0000000000000000000000000000000000000000000000000000000000000000"
  "3B6A27BCCEB6A42D62A3A8D02A6F0D73653215771DE243A63AC048A18B59DA29")

(deftest encode-check.4
  (with-elliptic-ed448
    (encode-check-private #x00))
  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "5B3AFE03878A49B28232D4F1A442AEBDE109F807ACEF7DFD9A7F65B962FE52D6547312CACECFF04337508F9D2529A8F1669169B21C32C48000")

(deftest encode-check.5
  (with-elliptic-secp256k1
    (encode-check-private #x01))
  "0000000000000000000000000000000000000000000000000000000000000001"
  "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")

(deftest encode-check.6
  (with-elliptic-secp256r1
    (encode-check-private #x01))
  "0000000000000000000000000000000000000000000000000000000000000001"
  "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")

(deftest encode-check.7
  (with-elliptic-ed25519
    (encode-check-private #x01))
  "0100000000000000000000000000000000000000000000000000000000000000"
  "CECC1507DC1DDD7295951C290888F095ADB9044D1B73D696E6DF065D683BD4FC")

(deftest encode-check.8
  (with-elliptic-ed448
    (encode-check-private #x00))
  "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "0572C14CB1307744B92F3837F99639ABBB20FFC471D89D9D545349DC700E0127491F061314FAF89A85C70760BD0188A5669D1A4393F0834B80")

(deftest encode-check.9
  (with-elliptic-secp256k1
    (encode-check-private #x12345678))
  "0000000000000000000000000000000000000000000000000000000012345678"
  "034CF7A9777C51AFD98A605CC8DC54787686E632D716EBC6F186D40760845344C3")

(deftest encode-check.10
  (with-elliptic-secp256r1
    (encode-check-private #x12345678))
  "0000000000000000000000000000000000000000000000000000000012345678"
  "02E40245B7DE085C2604AA63F2E80B72CC80FA7C46891628A4271B5FF88E2131CA")

(deftest encode-check.11
  (with-elliptic-ed25519
    (encode-check-private #x12345678))
  "7856341200000000000000000000000000000000000000000000000000000000"
  "487FBDF3E0B73CE5755840F821BE10D327729FBF612D2BB4F050ED34354447C9")

(deftest encode-check.12
  (with-elliptic-ed448
    (encode-check-private #x12345678))
  "785634120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "0281C83E14A86BC6A8CFA54F18E8677EC1FB4F08DA87712CBF243A394F7006DADD41ED2ABD4A7DBAFC11402854A280112910A53DDA30D2D200")

(defun verify-string (public message r s)
  (verify (decode2-string public)
          (map 'vector #'char-code message)
          (decode1-string r)
          (decode1-string s)))

(deftest elliptic-signature.1
  (with-elliptic-secp256k1
    (verify-string
      "03FEEF09658067CFBE3BE8685DDCE8E9C03B4A397ADC4A0255CE0B29FC63BCDC9C"
      "Hello"
      "7C7EDD22B0AED24D1B4A3826E228CE52EC897D52826D5912459238FC36008B86"
      "38C86C613A977CD5D1E024380FB56CDB924B0D972E903AB740F4E7F3A90F62BC"))
  t)

(deftest elliptic-signature.2
  (with-elliptic-secp256r1
    (verify-string
      "03CD92CF7B1C9CE9858383806B8540D72FB022BE577E21DE02B8EAA27371DB7AF2"
      "Hello"
      "FF6331919D62BFF9236113998250AB9079AA81C83085A27CC38A2CC0EEDDD98D"
      "1A374ADE37A61F6014C29C723C425BB3E6B519D517E16F66A46869F8EC535F89"))
  t)

(deftest elliptic-signature.3
  (with-elliptic-ed25519
    (verify-string
      "75AB16F53A060E7AF9A4B8ECEA3D4DEF058AED2C626FEC96D5505C4A7D922960"
      "Hello"
      "285D61D0DAC982F09365DA699DFD10A7B1B3A4D29A8468655A71F49965D4CEE1"
      "A58118E7ECAE263034F4BA7EB57BEE8D639C9BAF5BDE6BE97F2F864B3A1A7606"))
  t)

(deftest elliptic-signature.4
  (with-elliptic-ed448
    (verify-string
      "99AFC3768EE41B96F208EBAF8627908690DC6A5AC64659F93D0A46C2092B61E84AD14DD03F7B3F146799C29F65682126D517B7E1EA57716E00"
      "Hello"
      "DC38653AAD2F456132602EBC47571DABB56C36BA35D6965F820AFFB0FBE478439C7CF1D9EE7033792A23E80811CFAB07DC2B71DDEF526F6700"
      "0E11296ECFACEA4E5E9B795AC4048D711636BE468A99639F953ED1E948A6351F51DE0AE167EB268012E9712F7D6ADD97E80BB36E291C2A2D00"))
  t)


;;
;;  main
;;
(let ((*random-state* (make-random-state t)))
  (do-tests))

