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
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-secp256k1.2
  (with-elliptic-secp256k1
    (let* ((g *elliptic-g*)
           (x (encode g nil))
           (y (decode x)))
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-secp256k1.3
  (with-elliptic-secp256k1
    (let* ((g (doubling *elliptic-g*))
           (x (encode g t))
           (y (decode x)))
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-secp256k1.4
  (with-elliptic-secp256k1
    (let* ((g (doubling *elliptic-g*))
           (x (encode g nil))
           (y (decode x)))
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-secp256k1.5
  (with-elliptic-secp256k1
    (let* ((x (encode *elliptic-o* t))
           (y (decode x)))
      (neutral y)))
  t)

(deftest decode-secp256k1.6
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
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-secp256r1.2
  (with-elliptic-secp256r1
    (let* ((g *elliptic-g*)
           (x (encode g nil))
           (y (decode x)))
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-secp256r1.3
  (with-elliptic-secp256r1
    (let* ((g (doubling *elliptic-g*))
           (x (encode g t))
           (y (decode x)))
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-secp256r1.4
  (with-elliptic-secp256r1
    (let* ((g (doubling *elliptic-g*))
           (x (encode g nil))
           (y (decode x)))
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-secp256r1.5
  (with-elliptic-secp256r1
    (let* ((x (encode *elliptic-o* t))
           (y (decode x)))
      (neutral y)))
  t)

(deftest decode-secp256r1.6
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
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-ed25519.3
  (with-elliptic-ed25519
    (let* ((g (multiple 5 *elliptic-g*))  ;; 5G
           (x (encode g))
           (y (decode x)))
      (and (equal-point g y)
           (valid y))))
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
      (and (equal-point g y)
           (valid y))))
  t)

(deftest decode-ed448.3
  (with-elliptic-ed448
    (let* ((g (multiple 2 *elliptic-g*))  ;; 2G
           (x (encode g))
           (y (decode x)))
      (and (equal-point g y)
           (valid y))))
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
    (encode-check-private #x01))
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

(defun verify-rfc8032-string (private message r s)
  (verify (make-public (decode1-string private))
          (map 'vector #'char-code message)
          (decode1-string r)
          (decode1-string s)))

(deftest verify.1
  (with-elliptic-ed25519
    (verify-rfc8032-string
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
      ""
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"))
  t)


;;
;;  Diffie-Hellman
;;
(deftest curve25519-vector.1
  (with-elliptic-curve25519
    (let ((x "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
          (y "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
      (values
        (scalar1 (decode3-string x))
        (scalar2 (decode3-string y)))))
  31029842492115040904895560451863089656472772604678260265531221036453811406496
  34426434033919594451155107781188821651316167215306631574996226621102155684838)

(deftest curve25519-vector.2
  (with-elliptic-curve25519
    (let ((x "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
          (y "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
      (encode3-string
        (multiple-montgomery-x
          (scalar1 (decode3-string x))
          (scalar2 (decode3-string y))))))
  "C3DA55379DE9C6908E94EA4DF28D084F32ECCF03491C71F754B4075577A28552")

(deftest curve25519-vector.3
  (with-elliptic-curve25519
    (let ((x "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
          (y "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))
      (values
        (scalar1 (decode3-string x))
        (scalar2 (decode3-string y)))))
  35156891815674817266734212754503633747128614016119564763269015315466259359304
  8883857351183929894090759386610649319417338800022198945255395922347792736741)

(deftest curve25519-vector.4
  (with-elliptic-curve25519
    (let ((x "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
          (y "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))
      (encode3-string
        (multiple-montgomery-x
          (scalar1 (decode3-string x))
          (scalar2 (decode3-string y))))))
  "95CBDE9476E8907D7AADE45CB4B873F88B595A68799FA152E6F8F7647AAC7957")

(deftest curve448-vector.1
  (with-elliptic-curve448
    (let ((x "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3")
          (y "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"))
      (values
        (scalar1 (decode3-string x))
        (scalar2 (decode3-string y)))))
  599189175373896402783756016145213256157230856085026129926891459468622403380588640249457727683869421921443004045221642549886377526240828
  382239910814107330116229961234899377031416365240571325148346555922438025162094455820962429142971339584360034337310079791515452463053830)

(deftest curve448-vector.2
  (with-elliptic-curve448
    (let ((x "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3")
          (y "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"))
      (encode3-string
        (multiple-montgomery-x
          (scalar1 (decode3-string x))
          (scalar2 (decode3-string y))))))
  "CE3E4FF95A60DC6697DA1DB1D85E6AFBDF79B50A2412D7546D5F239FE14FBAADEB445FC66A01B0779D98223961111E21766282F73DD96B6F")

(deftest curve448-vector.3
  (with-elliptic-curve448
    (let ((x "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f")
          (y "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"))
      (values
        (scalar1 (decode3-string x))
        (scalar2 (decode3-string y)))))
  633254335906970592779259481534862372382525155252028961056404001332122152890562527156973881968934311400345568203929409663925541994577184
  622761797758325444462922068431234180649590390024811299761625153767228042600197997696167956134770744996690267634159427999832340166786063)

(deftest curve448-vector.4
  (with-elliptic-curve448
    (let ((x "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f")
          (y "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"))
      (encode3-string
        (multiple-montgomery-x
          (scalar1 (decode3-string x))
          (scalar2 (decode3-string y))))))
  "884A02576239FF7A2F2F63B2DB6A9FF37047AC13568E1E30FE63C4A7AD1B3EE3A5700DF34321D62077E63633C575C1C954514E99DA7C179D")

(deftest rfc7748-curve25519.1
  (with-elliptic-curve25519
    (let ((x "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
      (encode3-string
        (point2-x
          (make-public
            (scalar1
              (decode3-string x)))))))
  "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A")

(deftest rfc7748-curve25519.2
  (with-elliptic-curve25519
    (let ((x "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
      (encode3-string
        (point2-x
          (make-public
            (scalar1
              (decode3-string x)))))))
  "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F")

(deftest rfc7748-curve25519.3
  (with-elliptic-curve25519
    (let* ((a1 "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
           (a2 "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
           (b1 (scalar1 (decode3-string a1)))
           (b2 (scalar1 (decode3-string a2)))
           (c1 (make-public b1))
           (c2 (make-public b2))
           (d1 (multiple-montgomery b2 (point2-x c1)))
           (d2 (multiple-montgomery b1 (point2-x c2)))
           (e1 (encode3-string (point2-x d1)))
           (e2 (encode3-string (point2-x d2))))
      (values e1 e2)))
  "4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742"
  "4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742")

(deftest rfc7748-curve448.1
  (with-elliptic-curve448
    (let ((x "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"))
      (encode3-string
        (point2-x
          (make-public
            (scalar1
              (decode3-string x)))))))
  "9B08F7CC31B7E3E67D22D5AEA121074A273BD2B83DE09C63FAA73D2C22C5D9BBC836647241D953D40C5B12DA88120D53177F80E532C41FA0")

(deftest rfc7748-curve448.2
  (with-elliptic-curve448
    (let ((x "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"))
      (encode3-string
        (point2-x
          (make-public
            (scalar1
              (decode3-string x)))))))
  "3EB7A829B0CD20F5BCFC0B599B6FECCF6DA4627107BDB0D4F345B43027D8B972FC3E34FB4232A13CA706DCB57AEC3DAE07BDC1C67BF33609")

(deftest rfc7748-curve449.3
  (with-elliptic-curve448
    (let* ((a1 "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
           (a2 "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d")
           (b1 (scalar1 (decode3-string a1)))
           (b2 (scalar1 (decode3-string a2)))
           (c1 (make-public b1))
           (c2 (make-public b2))
           (d1 (multiple-montgomery b2 (point2-x c1)))
           (d2 (multiple-montgomery b1 (point2-x c2)))
           (e1 (encode3-string (point2-x d1)))
           (e2 (encode3-string (point2-x d2))))
      (values e1 e2)))
  "07FFF4181AC6CC95EC1C16A94A0F74D12DA232CE40A77552281D282BB60C0B56FD2464C335543936521C24403085D59A449A5037514A879D"
  "07FFF4181AC6CC95EC1C16A94A0F74D12DA232CE40A77552281D282BB60C0B56FD2464C335543936521C24403085D59A449A5037514A879D")

(defun ecccdh-check (pk px py qx qy)
  (let* ((p (make-public pk))
         (a (affine p)))
    (unless (and (eql (point2-x a) px)
                 (eql (point2-y a) py))
      (error "public key error.")))
  (let* ((q (make-point3 qx qy 1))
         (w (multiple pk q))
         (a (affine w)))
    (point2-x a)))

(defun ecccdh-check-secp256r1 (&rest args)
  (with-elliptic-secp256r1
    (apply #'ecccdh-check args)))

(defun ecccdh-check-secp384r1 (&rest args)
  (with-elliptic-secp384r1
    (apply #'ecccdh-check args)))

(defun ecccdh-check-secp521r1 (&rest args)
  (with-elliptic-secp521r1
    (apply #'ecccdh-check args)))

(deftest ecccdh-secp256r1.0
  (ecccdh-check-secp256r1
    #x7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534
    #xead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230
    #x28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141
    #x700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287
    #xdb71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac)
  #x46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B)

(deftest ecccdh-secp256r1.1
  (ecccdh-check-secp256r1
    #x38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5
    #x119f2f047902782ab0c9e27a54aff5eb9b964829ca99c06b02ddba95b0a3f6d0
    #x8f52b726664cac366fc98ac7a012b2682cbd962e5acb544671d41b9445704d1d
    #x809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae
    #xb29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3)
  #x057D636096CB80B67A8C038C890E887D1ADFA4195E9B3CE241C8A778C59CDA67)

(deftest ecccdh-secp256r1.2
  (ecccdh-check-secp256r1
    #x1accfaf1b97712b85a6f54b148985a1bdc4c9bec0bd258cad4b3d603f49f32c8
    #xd9f2b79c172845bfdb560bbb01447ca5ecc0470a09513b6126902c6b4f8d1051
    #xf815ef5ec32128d3487834764678702e64e164ff7315185e23aff5facd96d7bc
    #xa2339c12d4a03c33546de533268b4ad667debf458b464d77443636440ee7fec3
    #xef48a3ab26e20220bcda2c1851076839dae88eae962869a497bf73cb66faf536)
  #x2D457B78B4614132477618A5B077965EC90730A8C81A1C75D6D4EC68005D67EC)

(deftest ecccdh-secp256r1.3
  (ecccdh-check-secp256r1
    #x207c43a79bfee03db6f4b944f53d2fb76cc49ef1c9c4d34d51b6c65c4db6932d
    #x24277c33f450462dcb3d4801d57b9ced05188f16c28eda873258048cd1607e0d
    #xc4789753e2b1f63b32ff014ec42cd6a69fac81dfe6d0d6fd4af372ae27c46f88
    #xdf3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed
    #x422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4)
  #x96441259534B80F6AEE3D287A6BB17B5094DD4277D9E294F8FE73E48BF2A0024)

(deftest ecccdh-secp256r1.4
  (ecccdh-check-secp256r1
    #x59137e38152350b195c9718d39673d519838055ad908dd4757152fd8255c09bf
    #xa8c5fdce8b62c5ada598f141adb3b26cf254c280b2857a63d2ad783a73115f6b
    #x806e1aafec4af80a0d786b3de45375b517a7e5b51ffb2c356537c9e6ef227d4a
    #x41192d2813e79561e6a1d6f53c8bc1a433a199c835e141b05a74a97b0faeb922
    #x1af98cc45e98a7e041b01cf35f462b7562281351c8ebf3ffa02e33a0722a1328)
  #x19D44C8D63E8E8DD12C22A87B8CD4ECE27ACDDE04DBF47F7F27537A6999A8E62)

(deftest ecccdh-secp256r1.5
  (ecccdh-check-secp256r1
    #xf5f8e0174610a661277979b58ce5c90fee6c9b3bb346a90a7196255e40b132ef
    #x7b861dcd2844a5a8363f6b8ef8d493640f55879217189d80326aad9480dfc149
    #xc4675b45eeb306405f6c33c38bc69eb2bdec9b75ad5af4706aab84543b9cc63a
    #x33e82092a0f1fb38f5649d5867fba28b503172b7035574bf8e5b7100a3052792
    #xf2cf6b601e0a05945e335550bf648d782f46186c772c0f20d3cd0d6b8ca14b2f)
  #x664E45D5BBA4AC931CD65D52017E4BE9B19A515F669BEA4703542A2C525CD3D3)

(deftest ecccdh-secp256r1.6
  (ecccdh-check-secp256r1
    #x3b589af7db03459c23068b64f63f28d3c3c6bc25b5bf76ac05f35482888b5190
    #x9fb38e2d58ea1baf7622e96720101cae3cde4ba6c1e9fa26d9b1de0899102863
    #xd5561b900406edf50802dd7d73e89395f8aed72fba0e1d1b61fe1d22302260f0
    #x6a9e0c3f916e4e315c91147be571686d90464e8bf981d34a90b6353bca6eeba7
    #x40f9bead39c2f2bcc2602f75b8a73ec7bdffcbcead159d0174c6c4d3c5357f05)
  #xCA342DAA50DC09D61BE7C196C85E60A80C5CB04931746820BE548CDDE055679D)

(deftest ecccdh-secp256r1.7
  (ecccdh-check-secp256r1
    #xd8bf929a20ea7436b2461b541a11c80e61d826c0a4c9d322b31dd54e7f58b9c8
    #x20f07631e4a6512a89ad487c4e9d63039e579cb0d7a556cb9e661cd59c1e7fa4
    #x6de91846b3eee8a5ec09c2ab1f41e21bd83620ccdd1bdce3ab7ea6e02dd274f5
    #xa9c0acade55c2a73ead1a86fb0a9713223c82475791cd0e210b046412ce224bb
    #xf6de0afa20e93e078467c053d241903edad734c6b403ba758c2b5ff04c9d4229)
  #x35AA9B52536A461BFDE4E85FC756BE928C7DE97923F0416C7A3AC8F88B3D4489)

(deftest ecccdh-secp256r1.8
  (ecccdh-check-secp256r1
    #x0f9883ba0ef32ee75ded0d8bda39a5146a29f1f2507b3bd458dbea0b2bb05b4d
    #xabb61b423be5d6c26e21c605832c9142dc1dfe5a5fff28726737936e6fbf516d
    #x733d2513ef58beab202090586fac91bf0fee31e80ab33473ab23a2d89e58fad6
    #x94e94f16a98255fff2b9ac0c9598aac35487b3232d3231bd93b7db7df36f9eb9
    #xd8049a43579cfa90b8093a94416cbefbf93386f15b3f6e190b6e3455fedfe69a)
  #x605C16178A9BC875DCBFF54D63FE00DF699C03E8A888E9E94DFBAB90B25F39B4)

(deftest ecccdh-secp256r1.9
  (ecccdh-check-secp256r1
    #x2beedb04b05c6988f6a67500bb813faf2cae0d580c9253b6339e4a3337bb6c08
    #x3d63e429cb5fa895a9247129bf4e48e89f35d7b11de8158efeb3e106a2a87395
    #x0cae9e477ef41e7c8c1064379bb7b554ddcbcae79f9814281f1e50f0403c61f3
    #xe099bf2a4d557460b5544430bbf6da11004d127cb5d67f64ab07c94fcdf5274f
    #xd9c50dbe70d714edb5e221f4e020610eeb6270517e688ca64fb0e98c7ef8c1c5)
  #xF96E40A1B72840854BB62BC13C40CC2795E373D4E715980B261476835A092E0B)

(deftest ecccdh-secp256r1.10
  (ecccdh-check-secp256r1
    #x77c15dcf44610e41696bab758943eff1409333e4d5a11bbe72c8f6c395e9f848
    #xad5d13c3db508ddcd38457e5991434a251bed49cf5ddcb59cdee73865f138c9f
    #x62cec1e70588aa4fdfc7b9a09daa678081c04e1208b9d662b8a2214bf8e81a21
    #xf75a5fe56bda34f3c1396296626ef012dc07e4825838778a645c8248cff01658
    #x33bbdf1b1772d8059df568b061f3f1122f28a8d819167c97be448e3dc3fb0c3c)
  #x8388FA79C4BABDCA02A8E8A34F9E43554976E420A4AD273C81B26E4228E9D3A3)

(deftest ecccdh-secp256r1.11
  (ecccdh-check-secp256r1
    #x42a83b985011d12303db1a800f2610f74aa71cdf19c67d54ce6c9ed951e9093e
    #xab48caa61ea35f13f8ed07ffa6a13e8db224dfecfae1a7df8b1bb6ebaf0cb97d
    #x1274530ca2c385a3218bddfbcbf0b4024c9badd5243bff834ebff24a8618dccb
    #x2db4540d50230756158abf61d9835712b6486c74312183ccefcaef2797b7674d
    #x62f57f314e3f3495dc4e099012f5e0ba71770f9660a1eada54104cdfde77243e)
  #x72877CEA33CCC4715038D4BCBDFE0E43F42A9E2C0C3B017FC2370F4B9ACBDA4A)

(deftest ecccdh-secp256r1.12
  (ecccdh-check-secp256r1
    #xceed35507b5c93ead5989119b9ba342cfe38e6e638ba6eea343a55475de2800b
    #x9a8cd9bd72e71752df91440f77c547509a84df98114e7de4f26cdb39234a625d
    #xd07cfc84c8e144fab2839f5189bb1d7c88631d579bbc58012ed9a2327da52f62
    #xcd94fc9497e8990750309e9a8534fd114b0a6e54da89c4796101897041d14ecb
    #xc3def4b5fe04faee0a11932229fff563637bfdee0e79c6deeaf449f85401c5c4)
  #xE4E7408D85FF0E0E9C838003F28CDBD5247CDCE31F32F62494B70E5F1BC36307)

(deftest ecccdh-secp256r1.13
  (ecccdh-check-secp256r1
    #x43e0e9d95af4dc36483cdd1968d2b7eeb8611fcce77f3a4e7d059ae43e509604
    #xf989cf8ee956a82e7ebd9881cdbfb2fd946189b08db53559bc8cfdd48071eb14
    #x5eff28f1a18a616b04b7d337868679f6dd84f9a7b3d7b6f8af276c19611a541d
    #x15b9e467af4d290c417402e040426fe4cf236bae72baa392ed89780dfccdb471
    #xcdf4e9170fb904302b8fd93a820ba8cc7ed4efd3a6f2d6b05b80b2ff2aee4e77)
  #xED56BCF695B734142C24ECB1FC1BB64D08F175EB243A31F37B3D9BB4407F3B96)

(deftest ecccdh-secp256r1.14
  (ecccdh-check-secp256r1
    #xb2f3600df3368ef8a0bb85ab22f41fc0e5f4fdd54be8167a5c3cd4b08db04903
    #x69c627625b36a429c398b45c38677cb35d8beb1cf78a571e40e99fe4eac1cd4e
    #x81690112b0a88f20f7136b28d7d47e5fbc2ada3c8edd87589bc19ec9590637bd
    #x49c503ba6c4fa605182e186b5e81113f075bc11dcfd51c932fb21e951eee2fa1
    #x8af706ff0922d87b3f0c5e4e31d8b259aeb260a9269643ed520a13bb25da5924)
  #xBC5C7055089FC9D6C89F83C1EA1ADA879D9934B2EA28FCF4E4A7E984B28AD2CF)

(deftest ecccdh-secp256r1.15
  (ecccdh-check-secp256r1
    #x4002534307f8b62a9bf67ff641ddc60fef593b17c3341239e95bdb3e579bfdc8
    #x5fe964671315a18aa68a2a6e3dd1fde7e23b8ce7181471cfac43c99e1ae80262
    #xd5827be282e62c84de531b963884ba832db5d6b2c3a256f0e604fe7e6b8a7f72
    #x19b38de39fdd2f70f7091631a4f75d1993740ba9429162c2a45312401636b29c
    #x09aed7232b28e060941741b6828bcdfa2bc49cc844f3773611504f82a390a5ae)
  #x9A4E8E657F6B0E097F47954A63C75D74FCBA71A30D83651E3E5A91AA7CCD8343)

(deftest ecccdh-secp256r1.16
  (ecccdh-check-secp256r1
    #x4dfa12defc60319021b681b3ff84a10a511958c850939ed45635934ba4979147
    #xc9b2b8496f1440bd4a2d1e52752fd372835b364885e154a7dac49295f281ec7c
    #xfbe6b926a8a4de26ccc83b802b1212400754be25d9f3eeaf008b09870ae76321
    #x2c91c61f33adfe9311c942fdbff6ba47020feff416b7bb63cec13faf9b099954
    #x6cab31b06419e5221fca014fb84ec870622a1b12bab5ae43682aa7ea73ea08d0)
  #x3CA1FC7AD858FB1A6ABA232542F3E2A749FFC7203A2374A3F3D3267F1FC97B78)

(deftest ecccdh-secp256r1.17
  (ecccdh-check-secp256r1
    #x1331f6d874a4ed3bc4a2c6e9c74331d3039796314beee3b7152fcdba5556304e
    #x59e1e101521046ad9cf1d082e9d2ec7dd22530cce064991f1e55c5bcf5fcb591
    #x482f4f673176c8fdaa0bb6e59b15a3e47454e3a04297d3863c9338d98add1f37
    #xa28a2edf58025668f724aaf83a50956b7ac1cfbbff79b08c3bf87dfd2828d767
    #xdfa7bfffd4c766b86abeaf5c99b6e50cb9ccc9d9d00b7ffc7804b0491b67bc03)
  #x1AAABE7EE6E4A6FA732291202433A237DF1B49BC53866BFBE00DB96A0F58224F)

(deftest ecccdh-secp256r1.18
  (ecccdh-check-secp256r1
    #xdd5e9f70ae740073ca0204df60763fb6036c45709bf4a7bb4e671412fad65da3
    #x30b9db2e2e977bcdc98cb87dd736cbd8e78552121925cf16e1933657c2fb2314
    #x6a45028800b81291bce5c2e1fed7ded650620ebbe6050c6f3a7f0dfb4673ab5c
    #xa2ef857a081f9d6eb206a81c4cf78a802bdf598ae380c8886ecd85fdc1ed7644
    #x563c4c20419f07bc17d0539fade1855e34839515b892c0f5d26561f97fa04d1a)
  #x430E6A4FBA4449D700D2733E557F66A3BF3D50517C1271B1DDAE1161B7AC798C)

(deftest ecccdh-secp256r1.19
  (ecccdh-check-secp256r1
    #x5ae026cfc060d55600717e55b8a12e116d1d0df34af831979057607c2d9c2f76
    #x46c9ebd1a4a3c8c0b6d572b5dcfba12467603208a9cb5d2acfbb733c40cf6391
    #x46c913a27d044185d38b467ace011e04d4d9bbbb8cb9ae25fa92aaf15a595e86
    #xccd8a2d86bc92f2e01bce4d6922cf7fe1626aed044685e95e2eebd464505f01f
    #xe9ddd583a9635a667777d5b8a8f31b0f79eba12c75023410b54b8567dddc0f38)
  #x1CE9E6740529499F98D1F1D71329147A33DF1D05E4765B539B11CF615D6974D3)

(deftest ecccdh-secp256r1.20
  (ecccdh-check-secp256r1
    #xb601ac425d5dbf9e1735c5e2d5bdb79ca98b3d5be4a2cfd6f2273f150e064d9d
    #x7c9e950841d26c8dde8994398b8f5d475a022bc63de7773fcf8d552e01f1ba0a
    #xcc42b9885c9b3bee0f8d8c57d3a8f6355016c019c4062fa22cff2f209b5cc2e1
    #xc188ffc8947f7301fb7b53e36746097c2134bf9cc981ba74b4e9c4361f595e4e
    #xbf7d2f2056e72421ef393f0c0f2b0e00130e3cac4abbcc00286168e85ec55051)
  #x4690E3743C07D643F1BC183636AB2A9CB936A60A802113C49BB1B3F2D0661660)

(deftest ecccdh-secp256r1.21
  (ecccdh-check-secp256r1
    #xfefb1dda1845312b5fce6b81b2be205af2f3a274f5a212f66c0d9fc33d7ae535
    #x38b54db85500cb20c61056edd3d88b6a9dc26780a047f213a6e1b900f76596eb
    #x6387e4e5781571e4eb8ae62991a33b5dc33301c5bc7e125d53794a39160d8fd0
    #x317e1020ff53fccef18bf47bb7f2dd7707fb7b7a7578e04f35b3beed222a0eb6
    #x09420ce5a19d77c6fe1ee587e6a49fbaf8f280e8df033d75403302e5a27db2ae)
  #x30C2261BD0004E61FEDA2C16AA5E21FFA8D7E7F7DBF6EC379A43B48E4B36AEB0)

(deftest ecccdh-secp256r1.22
  (ecccdh-check-secp256r1
    #x334ae0c4693d23935a7e8e043ebbde21e168a7cba3fa507c9be41d7681e049ce
    #x3f2bf1589abf3047bf3e54ac9a95379bff95f8f55405f64eca36a7eebe8ffca7
    #x5212a94e66c5ae9a8991872f66a72723d80ec5b2e925745c456f5371943b3a06
    #x45fb02b2ceb9d7c79d9c2fa93e9c7967c2fa4df5789f9640b24264b1e524fcb1
    #x5c6e8ecf1f7d3023893b7b1ca1e4d178972ee2a230757ddc564ffe37f5c5a321)
  #x2ADAE4A138A239DCD93C243A3803C3E4CF96E37FE14E6A9B717BE9599959B11C)

(deftest ecccdh-secp256r1.23
  (ecccdh-check-secp256r1
    #x2c4bde40214fcc3bfc47d4cf434b629acbe9157f8fd0282540331de7942cf09d
    #x29c0807f10cbc42fb45c9989da50681eead716daa7b9e91fd32e062f5eb92ca0
    #xff1d6d1955d7376b2da24fe1163a271659136341bc2eb1195fc706dc62e7f34d
    #xa19ef7bff98ada781842fbfc51a47aff39b5935a1c7d9625c8d323d511c92de6
    #xe9c184df75c955e02e02e400ffe45f78f339e1afe6d056fb3245f4700ce606ef)
  #x2E277EC30F5EA07D6CE513149B9479B96E07F4B6913B1B5C11305C1444A1BC0B)

(deftest ecccdh-secp256r1.24
  (ecccdh-check-secp256r1
    #x85a268f9d7772f990c36b42b0a331adc92b5941de0b862d5d89a347cbf8faab0
    #x9cf4b98581ca1779453cc816ff28b4100af56cf1bf2e5bc312d83b6b1b21d333
    #x7a5504fcac5231a0d12d658218284868229c844a04a3450d6c7381abe080bf3b
    #x356c5a444c049a52fee0adeb7e5d82ae5aa83030bfff31bbf8ce2096cf161c4b
    #x57d128de8b2a57a094d1a001e572173f96e8866ae352bf29cddaf92fc85b2f92)
  #x1E51373BD2C6044C129C436E742A55BE2A668A85AE08441B6756445DF5493857)

(deftest ecccdh-secp384r1.0
  (ecccdh-check-secp384r1
    #x3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1
    #x9803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5f
    #xba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99
    #xa7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066
    #xac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a)
  #x5F9D29DC5E31A163060356213669C8CE132E22F57C9A04F40BA7FCEAD493B457E5621E766C40A2E3D4D6A04B25E533F1)

(deftest ecccdh-secp384r1.1
  (ecccdh-check-secp384r1
    #x92860c21bde06165f8e900c687f8ef0a05d14f290b3f07d8b3a8cc6404366e5d5119cd6d03fb12dc58e89f13df9cd783
    #xea4018f5a307c379180bf6a62fd2ceceebeeb7d4df063a66fb838aa35243419791f7e2c9d4803c9319aa0eb03c416b66
    #x68835a91484f05ef028284df6436fb88ffebabcdd69ab0133e6735a1bcfb37203d10d340a8328a7b68770ca75878a1a6
    #x30f43fcf2b6b00de53f624f1543090681839717d53c7c955d1d69efaf0349b7363acb447240101cbb3af6641ce4b88e0
    #x25e46c0c54f0162a77efcc27b6ea792002ae2ba82714299c860857a68153ab62e525ec0530d81b5aa15897981e858757)
  #xA23742A2C267D7425FDA94B93F93BBCC24791AC51CD8FD501A238D40812F4CBFC59AAC9520D758CF789C76300C69D2FF)

(deftest ecccdh-secp384r1.2
  (ecccdh-check-secp384r1
    #x12cf6a223a72352543830f3f18530d5cb37f26880a0b294482c8a8ef8afad09aa78b7dc2f2789a78c66af5d1cc553853
    #xfcfcea085e8cf74d0dced1620ba8423694f903a219bbf901b0b59d6ac81baad316a242ba32bde85cb248119b852fab66
    #x972e3c68c7ab402c5836f2a16ed451a33120a7750a6039f3ff15388ee622b7065f7122bf6d51aefbc29b37b03404581b
    #x1aefbfa2c6c8c855a1a216774550b79a24cda37607bb1f7cc906650ee4b3816d68f6a9c75da6e4242cebfb6652f65180
    #x419d28b723ebadb7658fcebb9ad9b7adea674f1da3dc6b6397b55da0f61a3eddacb4acdb14441cb214b04a0844c02fa3)
  #x3D2E640F350805EED1FF43B40A72B2ABED0A518BCEBE8F2D15B111B6773223DA3C3489121DB173D414B5BD5AD7153435)

(deftest ecccdh-secp384r1.3
  (ecccdh-check-secp384r1
    #x8dd48063a3a058c334b5cc7a4ce07d02e5ee6d8f1f3c51a1600962cbab462690ae3cd974fb39e40b0e843daa0fd32de1
    #xe38c9846248123c3421861ea4d32669a7b5c3c08376ad28104399494c84ff5efa3894adb2c6cbe8c3c913ef2eec5bd3c
    #x9fa84024a1028796df84021f7b6c9d02f0f4bd1a612a03cbf75a0beea43fef8ae84b48c60172aadf09c1ad016d0bf3ce
    #x8bc089326ec55b9cf59b34f0eb754d93596ca290fcb3444c83d4de3a5607037ec397683f8cef07eab2fe357eae36c449
    #xd9d16ce8ac85b3f1e94568521aae534e67139e310ec72693526aa2e927b5b322c95a1a033c229cb6770c957cd3148dd7)
  #x6A42CFC392ABA0BFD3D17B7CCF062B91FC09BBF3417612D02A90BDDE62AE40C54BB2E56E167D6B70DB670097EB8DB854)

(deftest ecccdh-secp384r1.4
  (ecccdh-check-secp384r1
    #x84ece6cc3429309bd5b23e959793ed2b111ec5cb43b6c18085fcaea9efa0685d98a6262ee0d330ee250bc8a67d0e733f
    #x3222063a2997b302ee60ee1961108ff4c7acf1c0ef1d5fb0d164b84bce71c431705cb9aea9a45f5d73806655a058bee3
    #xe61fa9e7fbe7cd43abf99596a3d3a039e99fa9dc93b0bdd9cad81966d17eeaf557068afa7c78466bb5b22032d1100fa6
    #xeb952e2d9ac0c20c6cc48fb225c2ad154f53c8750b003fd3b4ed8ed1dc0defac61bcdde02a2bcfee7067d75d342ed2b0
    #xf1828205baece82d1b267d0d7ff2f9c9e15b69a72df47058a97f3891005d1fb38858f5603de840e591dfa4f6e7d489e1)
  #xCE7BA454D4412729A32BB833A2D1FD2AE612D4667C3A900E069214818613447DF8C611DE66DA200DB7C375CF913E4405)

(deftest ecccdh-secp384r1.5
  (ecccdh-check-secp384r1
    #x68fce2121dc3a1e37b10f1dde309f9e2e18fac47cd1770951451c3484cdb77cb136d00e731260597cc2859601c01a25b
    #x868be0e694841830e424d913d8e7d86b84ee1021d82b0ecf523f09fe89a76c0c95c49f2dfbcf829c1e39709d55efbb3b
    #x9195eb183675b40fd92f51f37713317e4a9b4f715c8ab22e0773b1bc71d3a219f05b8116074658ee86b52e36f3897116
    #x441d029e244eb7168d647d4df50db5f4e4974ab3fdaf022aff058b3695d0b8c814cc88da6285dc6df1ac55c553885003
    #xe8025ac23a41d4b1ea2aa46c50c6e479946b59b6d76497cd9249977e0bfe4a6262622f13d42a3c43d66bdbb30403c345)
  #xBA69F0ACDF3E1CA95CAAAC4ECAF475BBE51B54777EFCE01CA381F45370E486FE87F9F419B150C61E329A286D1AA265EC)

(deftest ecccdh-secp384r1.6
  (ecccdh-check-secp384r1
    #xb1764c54897e7aae6de9e7751f2f37de849291f88f0f91093155b858d1cc32a3a87980f706b86cc83f927bdfdbeae0bd
    #xc371222feaa6770c6f3ea3e0dac9740def4fcf821378b7f91ff937c21e0470f70f3a31d5c6b2912195f10926942b48ae
    #x047d6b4d765123563f81116bc665b7b8cc6207830d805fd84da7cb805a65baa7c12fd592d1b5b5e3e65d9672a9ef7662
    #x3d4e6bf08a73404accc1629873468e4269e82d90d832e58ad72142639b5a056ad8d35c66c60e8149fac0c797bceb7c2f
    #x9b0308dc7f0e6d29f8c277acbc65a21e5adb83d11e6873bc0a07fda0997f482504602f59e10bc5cb476b83d0a4f75e71)
  #x1A6688EE1D6E59865D8E3ADA37781D36BB0C2717EEF92E61964D3927CB765C2965EA80F7F63E58C322BA0397FAEAF62B)

(deftest ecccdh-secp384r1.7
  (ecccdh-check-secp384r1
    #xf0f7a96e70d98fd5a30ad6406cf56eb5b72a510e9f192f50e1f84524dbf3d2439f7287bb36f5aa912a79deaab4adea82
    #x99c8c41cb1ab5e0854a346e4b08a537c1706a61553387c8d94943ab15196d40dbaa55b8210a77a5d00915f2c4ea69eab
    #x5531065bdcf17bfb3cb55a02e41a57c7f694c383ad289f900fbd656c2233a93c92e933e7a26f54cbb56f0ad875c51bb0
    #xf5f6bef1d110da03be0017eac760cc34b24d092f736f237bc7054b3865312a813bcb62d297fb10a4f7abf54708fe2d3d
    #x06fdf8d7dc032f4e10010bf19cbf6159321252ff415fb91920d438f24e67e60c2eb0463204679fa356af44cea9c9ebf5)
  #xD06A568BF2336B90CBAC325161BE7695EACB2295F599500D787F072612ACA313EE5D874F807DDEF6C1F023FE2B6E7CD0)

(deftest ecccdh-secp384r1.8
  (ecccdh-check-secp384r1
    #x9efb87ddc61d43c482ba66e1b143aef678fbd0d1bebc2000941fabe677fe5b706bf78fce36d100b17cc787ead74bbca2
    #x4c34efee8f0c95565d2065d1bbac2a2dd25ae964320eb6bccedc5f3a9b42a881a1afca1bb6b880584fa27b01c193cd92
    #xd8fb01dbf7cd0a3868c26b951f393c3c56c2858cee901f7793ff5d271925d13a41f8e52409f4eba1990f33acb0bac669
    #x7cdec77e0737ea37c67b89b7137fe38818010f4464438ee4d1d35a0c488cad3fde2f37d00885d36d3b795b9f93d23a67
    #x28c42ee8d6027c56cf979ba4c229fdb01d234944f8ac433650112c3cf0f02844e888a3569dfef7828a8a884589aa055e)
  #xBB3B1EDA9C6560D82FF5BEE403339F1E80342338A991344853B56B24F109A4D94B92F654F0425EDD4C205903D7586104)

(deftest ecccdh-secp384r1.9
  (ecccdh-check-secp384r1
    #xd787a57fde22ec656a0a525cf3c738b30d73af61e743ea90893ecb2d7b622add2f94ee25c2171467afb093f3f84d0018
    #x171546923b87b2cbbad664f01ce932bf09d6a6118168678446bfa9f0938608cb4667a98f4ec8ac1462285c2508f74862
    #xfa41cb4db68ae71f1f8a3e8939dc52c2dec61a83c983beb2a02baf29ec49278088882ed0cf56c74b5c173b552ccf63cf
    #x8eeea3a319c8df99fbc29cb55f243a720d95509515ee5cc587a5c5ae22fbbd009e626db3e911def0b99a4f7ae304b1ba
    #x73877dc94db9adddc0d9a4b24e8976c22d73c844370e1ee857f8d1b129a3bd5f63f40caf3bd0533e38a5f5777074ff9e)
  #x1E97B60ADD7CB35C7403DD884C0A75795B7683FFF8B49F9D8672A8206BFDCF0A106B8768F983258C74167422E44E4D14)

(deftest ecccdh-secp384r1.10
  (ecccdh-check-secp384r1
    #x83d70f7b164d9f4c227c767046b20eb34dfc778f5387e32e834b1e6daec20edb8ca5bb4192093f543b68e6aeb7ce788b
    #x57cd770f3bbcbe0c78c770eab0b169bc45e139f86378ffae1c2b16966727c2f2eb724572b8f3eb228d130db4ff862c63
    #x7ec5c8813b685558d83e924f14bc719f6eb7ae0cbb2c474227c5bda88637a4f26c64817929af999592da6f787490332f
    #xa721f6a2d4527411834b13d4d3a33c29beb83ab7682465c6cbaf6624aca6ea58c30eb0f29dd842886695400d7254f20f
    #x14ba6e26355109ad35129366d5e3a640ae798505a7fa55a96a36b5dad33de00474f6670f522214dd7952140ab0a7eb68)
  #x1023478840E54775BFC69293A3CF97F5BC914726455C66538EB5623E218FEEF7DF4BEFA23E09D77145AD577DB32B41F9)

(deftest ecccdh-secp384r1.11
  (ecccdh-check-secp384r1
    #x8f558e05818b88ed383d5fca962e53413db1a0e4637eda194f761944cbea114ab9d5da175a7d57882550b0e432f395a9
    #x9a2f57f4867ce753d72b0d95195df6f96c1fae934f602efd7b6a54582f556cfa539d89005ca2edac08ad9b72dd1f60ba
    #xd9b94ee82da9cc601f346044998ba387aee56404dc6ecc8ab2b590443319d0b2b6176f9d0eac2d44678ed561607d09a9
    #xd882a8505c2d5cb9b8851fc676677bb0087681ad53faceba1738286b45827561e7da37b880276c656cfc38b32ade847e
    #x34b314bdc134575654573cffaf40445da2e6aaf987f7e913cd4c3091523058984a25d8f21da8326192456c6a0fa5f60c)
  #x6AD6B9DC8A6CF0D3691C501CBB967867F6E4BBB764B60DBFF8FCFF3ED42DBBA39D63CF325B4B4078858495DDEE75F954)

(deftest ecccdh-secp384r1.12
  (ecccdh-check-secp384r1
    #x0f5dee0affa7bbf239d5dff32987ebb7cf84fcceed643e1d3c62d0b3352aec23b6e5ac7fa4105c8cb26126ad2d1892cb
    #x23346bdfbc9d7c7c736e02bdf607671ff6082fdd27334a8bc75f3b23681ebe614d0597dd614fae58677c835a9f0b273b
    #x82ba36290d2f94db41479eb45ab4eaf67928a2315138d59eecc9b5285dfddd6714f77557216ea44cc6fc119d8243efaf
    #x815c9d773dbf5fb6a1b86799966247f4006a23c92e68c55e9eaa998b17d8832dd4d84d927d831d4f68dac67c6488219f
    #xe79269948b2611484560fd490feec887cb55ef99a4b524880fa7499d6a07283aae2afa33feab97deca40bc606c4d8764)
  #xCC9E063566D46B357B3FCAE21827377331E5E290A36E60CD7C39102B828AE0B918DC5A02216B07FE6F1958D834E42437)

(deftest ecccdh-secp384r1.13
  (ecccdh-check-secp384r1
    #x037b633b5b8ba857c0fc85656868232e2febf59578718391b81da8541a00bfe53c30ae04151847f27499f8d7abad8cf4
    #x8878ac8a947f7d5cb2b47aad24fbb8210d86126585399a2871f84aa9c5fde3074ae540c6bf82275ca822d0feb862bc74
    #x632f5cd2f900c2711c32f8930728eb647d31edd8d650f9654e7d33e5ed1b475489d08daa30d8cbcba6bfc3b60d9b5a37
    #x1c0eeda7a2be000c5bdcda0478aed4db733d2a9e341224379123ad847030f29e3b168fa18e89a3c0fba2a6ce1c28fc3b
    #xec8c1c83c118c4dbea94271869f2d868eb65e8b44e21e6f14b0f4d9b38c068daefa27114255b9a41d084cc4a1ad85456)
  #xDEFF7F03BD09865BAF945E73EDFF6D5122C03FB561DB87DEC8662E09BED4340B28A9EFE118337BB7D3D4F7F568635FF9)

(deftest ecccdh-secp384r1.14
  (ecccdh-check-secp384r1
    #xe3d07106bedcc096e7d91630ffd3094df2c7859db8d7edbb2e37b4ac47f429a637d06a67d2fba33838764ef203464991
    #xe74a1a2b85f1cbf8dbbdf050cf1aff8acb02fda2fb6591f9d3cfe4e79d0ae938a9c1483e7b75f8db24505d65065cdb18
    #x1773ee591822f7abaa856a1a60bc0a5203548dbd1cb5025466eff8481bd07614eaa04a16c3db76905913e972a5b6b59d
    #xc95c185e256bf997f30b311548ae7f768a38dee43eeeef43083f3077be70e2bf39ac1d4daf360c514c8c6be623443d1a
    #x3e63a663eaf75d8a765ab2b9a35513d7933fa5e26420a5244550ec6c3b6f033b96db2aca3d6ac6aab052ce929595aea5)
  #xC8B1038F735AD3BB3E4637C3E47EAB487637911A6B7950A4E461948329D3923B969E5DB663675623611A457FCDA35A71)

(deftest ecccdh-secp384r1.15
  (ecccdh-check-secp384r1
    #xf3f9b0c65a49a506632c8a45b10f66b5316f9eeb06fae218f2da62333f99905117b141c760e8974efc4af10570635791
    #xa4ad77aa7d86e5361118a6b921710c820721210712f4c347985fdee58aa4effa1e28be80a17b120b139f96300f89b49b
    #x1ddf22e07e03f1560d8f45a480094560dba9fae7f9531130c1b57ebb95982496524f31d3797793396fa823f22bdb4328
    #x3497238a7e6ad166df2dac039aa4dac8d17aa925e7c7631eb3b56e3aaa1c545fcd54d2e5985807910fb202b1fc191d2a
    #xa49e5c487dcc7aa40a8f234c979446040d9174e3ad357d404d7765183195aed3f913641b90c81a306ebf0d8913861316)
  #xD337EAA32B9F716B8747B005B97A553C59DAB0C51DF41A2D49039CDAE705AA75C7B9E7BC0B6A0E8C578C902BC4FFF23E)

(deftest ecccdh-secp384r1.16
  (ecccdh-check-secp384r1
    #x59fce7fad7de28bac0230690c95710c720e528f9a4e54d3a6a8cd5fc5c5f21637031ce1c5b4e3d39647d8dcb9b794664
    #x9c43bf971edf09402876ee742095381f78b1bd3aa39b5132af75dbfe7e98bd78bde10fe2e903c2b6379e1deee175a1b0
    #xa6c58ecea5a477bb01bd543b339f1cc49f1371a2cda4d46eb4e53e250597942351a99665a122ffea9bde0636c375daf2
    #x90a34737d45b1aa65f74e0bd0659bc118f8e4b774b761944ffa6573c6df4f41dec0d11b697abd934d390871d4b453240
    #x9b590719bb3307c149a7817be355d684893a307764b512eeffe07cb699edb5a6ffbf8d6032e6c79d5e93e94212c2aa4e)
  #x32D292B695A4488E42A7B7922E1AE537D76A3D21A0B2E36875F60E9F6D3E8779C2AFB3A413B9DD79AE18E70B47D337C1)

(deftest ecccdh-secp384r1.17
  (ecccdh-check-secp384r1
    #x3e49fbf950a424c5d80228dc4bc35e9f6c6c0c1d04440998da0a609a877575dbe437d6a5cedaa2ddd2a1a17fd112aded
    #x5a949594228b1a3d6f599eb3db0d06070fbc551c657b58234ba164ce3fe415fa5f3eb823c08dc29b8c341219c77b6b3d
    #x2baad447c8c290cfed25edd9031c41d0b76921457327f42db31122b81f337bbf0b1039ec830ce9061a3761953c75e4a8
    #xdda546acfc8f903d11e2e3920669636d44b2068aeb66ff07aa266f0030e1535b0ed0203cb8a460ac990f1394faf22f1d
    #x15bbb2597913035faadf413476f4c70f7279769a40c986f470c427b4ee4962abdf8173bbad81874772925fd32f0b159f)
  #x1220E7E6CAD7B25DF98E5BBDCC6C0B65CA6C2A50C5FF6C41DCA71E475646FD489615979CA92FB4389AEADEFDE79A24F1)

(deftest ecccdh-secp384r1.18
  (ecccdh-check-secp384r1
    #x50ccc1f7076e92f4638e85f2db98e0b483e6e2204c92bdd440a6deea04e37a07c6e72791c190ad4e4e86e01efba84269
    #x756c07df0ce32c839dac9fb4733c9c28b70113a676a7057c38d223f22a3a9095a8d564653af528e04c7e1824be4a6512
    #x17c2ce6962cbd2a2e066297b39d57dd9bb4680f0191d390f70b4e461419b2972ce68ad46127fdda6c39195774ea86df3
    #x788be2336c52f4454d63ee944b1e49bfb619a08371048e6da92e584eae70bde1f171c4df378bd1f3c0ab03048a237802
    #x4673ebd8db604eaf41711748bab2968a23ca4476ce144e728247f08af752929157b5830f1e26067466bdfa8b65145a33)
  #x793BB9CD22A93CF468FAF804A38D12B78CB12189EC679DDD2E9AA21FA9A5A0B049AB16A23574FE04C1C3C02343B91BEB)

(deftest ecccdh-secp384r1.19
  (ecccdh-check-secp384r1
    #x06f132b71f74d87bf99857e1e4350a594e5fe35533b888552ceccbc0d8923c902e36141d7691e28631b8bc9bafe5e064
    #x2a3cc6b8ff5cde926e7e3a189a1bd029c9b586351af8838f4f201cb8f4b70ef3b0da06d352c80fc26baf8f42b784459e
    #xbf9985960176da6d23c7452a2954ffcbbcb24249b43019a2a023e0b3dabd461f19ad3e775c364f3f11ad49f3099400d3
    #xd09bb822eb99e38060954747c82bb3278cf96bbf36fece3400f4c873838a40c135eb3babb9293bd1001bf3ecdee7bf26
    #xd416db6e1b87bbb7427788a3b6c7a7ab2c165b1e366f9608df512037584f213a648d47f16ac326e19aae972f63fd76c9)
  #x012D191CF7404A523678C6FC075DE8285B243720A903047708BB33E501E0DBEE5BCC40D7C3EF6C6DA39EA24D830DA1E8)

(deftest ecccdh-secp384r1.20
  (ecccdh-check-secp384r1
    #x12048ebb4331ec19a1e23f1a2c773b664ccfe90a28bfb846fc12f81dff44b7443c77647164bf1e9e67fd2c07a6766241
    #xbc18836bc7a9fdf54b5352f37d7528ab8fa8ec544a8c6180511cbfdd49cce377c39e34c031b5240dc9980503ed2f262c
    #x8086cbe338191080f0b7a16c7afc4c7b0326f9ac66f58552ef4bb9d24de3429ed5d3277ed58fcf48f2b5f61326bec6c6
    #x13741262ede5861dad71063dfd204b91ea1d3b7c631df68eb949969527d79a1dc59295ef7d2bca6743e8cd77b04d1b58
    #x0baaeadc7e19d74a8a04451a135f1be1b02fe299f9dc00bfdf201e83d995c6950bcc1cb89d6f7b30bf54656b9a4da586)
  #xAD0FD3DDFFE8884B9263F3C15FE1F07F2A5A22FFDC7E967085EEA45F0CD959F20F18F522763E28BCC925E496A52DDA98)

(deftest ecccdh-secp384r1.21
  (ecccdh-check-secp384r1
    #x34d61a699ca576169fcdc0cc7e44e4e1221db0fe63d16850c8104029f7d48449714b9884328cae189978754ab460b486
    #x867f81104ccd6b163a7902b670ef406042cb0cce7dcdc63d1dfc91b2c40e3cdf7595834bf9eceb79849f1636fc8462fc
    #x9d4bde8e875ec49697d258d1d59465f8431c6f5531e1c59e9f9ebe3cf164a8d9ce10a12f1979283a959bad244dd83863
    #x9e22cbc18657f516a864b37b783348b66f1aa9626cd631f4fa1bd32ad88cf11db52057c660860d39d11fbf024fabd444
    #x6b0d53c79681c28116df71e9cee74fd56c8b7f04b39f1198cc72284e98be9562e35926fb4f48a9fbecafe729309e8b6f)
  #xDC4CA392DC15E20185F2C6A8EA5EC31DFC96F56153A47394B3072B13D0015F5D4AE13BEB3BED54D65848F9B8383E6C95)

(deftest ecccdh-secp384r1.22
  (ecccdh-check-secp384r1
    #xdc60fa8736d702135ff16aab992bb88eac397f5972456c72ec447374d0d8ce61153831bfc86ad5a6eb5b60bfb96a862c
    #xb69beede85d0f829fec1b893ccb9c3e052ff692e13b974537bc5b0f9feaf7b22e84f03231629b24866bdb4b8cf908914
    #x66f85e2bfcaba2843285b0e14ebc07ef7dafff8b424416fee647b59897b619f20eed95a632e6a4206bf7da429c04c560
    #x2db5da5f940eaa884f4db5ec2139b0469f38e4e6fbbcc52df15c0f7cf7fcb1808c749764b6be85d2fdc5b16f58ad5dc0
    #x22e8b02dcf33e1b5a083849545f84ad5e43f77cb71546dbbac0d11bdb2ee202e9d3872e8d028c08990746c5e1dde9989)
  #xD765B208112D2B9ED5AD10C4046E2E3B0DBF57C469329519E239AC28B25C7D852BF757D5DE0EE271CADD021D86CFD347)

(deftest ecccdh-secp384r1.23
  (ecccdh-check-secp384r1
    #x6fa6a1c704730987aa634b0516a826aba8c6d6411d3a4c89772d7a62610256a2e2f289f5c3440b0ec1e70fa339e251ce
    #x53de1fc1328e8de14aecab29ad8a40d6b13768f86f7d298433d20fec791f86f8bc73f358098b256a298bb488de257bf4
    #xac28944fd27f17b82946c04c66c41f0053d3692f275da55cd8739a95bd8cd3af2f96e4de959ea8344d8945375905858b
    #x329647baa354224eb4414829c5368c82d7893b39804e08cbb2180f459befc4b347a389a70c91a23bd9d30c83be5295d3
    #xcc8f61923fad2aa8e505d6cfa126b9fabd5af9dce290b75660ef06d1caa73681d06089c33bc4246b3aa30dbcd2435b12)
  #xD3778850AEB58804FBE9DFE6F38B9FA8E20C2CA4E0DEC335AAFCECA0333E3F2490B53C0C1A14A831BA37C4B9D74BE0F2)

(deftest ecccdh-secp384r1.24
  (ecccdh-check-secp384r1
    #x74ad8386c1cb2ca0fcdeb31e0869bb3f48c036afe2ef110ca302bc8b910f621c9fcc54cec32bb89ec7caa84c7b8e54a8
    #x27a3e83cfb9d5122e73129d801615857da7cc089cccc9c54ab3032a19e0a0a9f677346e37f08a0b3ed8da6e5dd691063
    #x8d60e44aa5e0fd30c918456796af37f0e41957901645e5c596c6d989f5859b03a0bd7d1f4e77936fff3c74d204e5388e
    #x29d8a36d22200a75b7aea1bb47cdfcb1b7fd66de967041434728ab5d533a060df732130600fe6f75852a871fb2938e39
    #xe19b53db528395de897a45108967715eb8cb55c3fcbf23379372c0873a058d57544b102ecce722b2ccabb1a603774fd5)
  #x81E1E71575BB4505498DE097350186430A6242FA6C57B85A5F984A23371123D2D1424EEFBF804258392BC723E4EF1E35)

(deftest ecccdh-secp521r1.0
  (ecccdh-check-secp521r1
    #x0000017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47
    #x000000602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a5
    #x000001b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d
    #x000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d
    #x000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676)
  #x005FC70477C3E63BC3954BD0DF3EA0D1F41EE21746ED95FC5E1FDF90930D5E136672D72CC770742D1711C3C3A4C334A0AD9759436A4D3C5BF6E74B9578FAC148C831)

(deftest ecccdh-secp521r1.1
  (ecccdh-check-secp521r1
    #x000000816f19c1fb10ef94d4a1d81c156ec3d1de08b66761f03f06ee4bb9dcebbbfe1eaa1ed49a6a990838d8ed318c14d74cc872f95d05d07ad50f621ceb620cd905cfb8
    #x000000d45615ed5d37fde699610a62cd43ba76bedd8f85ed31005fe00d6450fbbd101291abd96d4945a8b57bc73b3fe9f4671105309ec9b6879d0551d930dac8ba45d255
    #x000001425332844e592b440c0027972ad1526431c06732df19cd46a242172d4dd67c2c8c99dfc22e49949a56cf90c6473635ce82f25b33682fb19bc33bd910ed8ce3a7fa
    #x000001df277c152108349bc34d539ee0cf06b24f5d3500677b4445453ccc21409453aafb8a72a0be9ebe54d12270aa51b3ab7f316aa5e74a951c5e53f74cd95fc29aee7a
    #x0000013d52f33a9f3c14384d1587fa8abe7aed74bc33749ad9c570b471776422c7d4505d9b0a96b3bfac041e4c6a6990ae7f700e5b4a6640229112deafa0cd8bb0d089b0)
  #x000B3920AC830ADE812C8F96805DA2236E002ACBBF13596A9AB254D44D0E91B6255EBF1229F366FB5A05C5884EF46032C26D42189273CA4EFA4C3DB6BD12A6853759)

(deftest ecccdh-secp521r1.2
  (ecccdh-check-secp521r1
    #x0000012f2e0c6d9e9d117ceb9723bced02eb3d4eebf5feeaf8ee0113ccd8057b13ddd416e0b74280c2d0ba8ed291c443bc1b141caf8afb3a71f97f57c225c03e1e4d42b0
    #x000000717fcb3d4a40d103871ede044dc803db508aaa4ae74b70b9fb8d8dfd84bfecfad17871879698c292d2fd5e17b4f9343636c531a4fac68a35a93665546b9a878679
    #x000000f3d96a8637036993ab5d244500fff9d2772112826f6436603d3eb234a44d5c4e5c577234679c4f9df725ee5b9118f23d8a58d0cc01096daf70e8dfec0128bdc2e8
    #x00000092db3142564d27a5f0006f819908fba1b85038a5bc2509906a497daac67fd7aee0fc2daba4e4334eeaef0e0019204b471cd88024f82115d8149cc0cf4f7ce1a4d5
    #x0000016bad0623f517b158d9881841d2571efbad63f85cbe2e581960c5d670601a6760272675a548996217e4ab2b8ebce31d71fca63fcc3c08e91c1d8edd91cf6fe845f8)
  #x006B380A6E95679277CFEE4E8353BF96EF2A1EBDD060749F2F046FE571053740BBCC9A0B55790BC9AB56C3208AA05DDF746A10A3AD694DAAE00D980D944AABC6A08F)

(deftest ecccdh-secp521r1.3
  (ecccdh-check-secp521r1
    #x000000e548a79d8b05f923b9825d11b656f222e8cb98b0f89de1d317184dc5a698f7c71161ee7dc11cd31f4f4f8ae3a981e1a3e78bdebb97d7c204b9261b4ef92e0918e0
    #x0000000ce800217ed243dd10a79ad73df578aa8a3f9194af528cd1094bbfee27a3b5481ad5862c8876c0c3f91294c0ab3aa806d9020cbaa2ed72b7fecdc5a09a6dad6f32
    #x000001543c9ab45b12469232918e21d5a351f9a4b9cbf9efb2afcc402fa9b31650bec2d641a05c440d35331c0893d11fb13151335988b303341301a73dc5f61d574e67d9
    #x000000fdd40d9e9d974027cb3bae682162eac1328ad61bc4353c45bf5afe76bf607d2894c8cce23695d920f2464fda4773d4693be4b3773584691bdb0329b7f4c86cc299
    #x00000034ceac6a3fef1c3e1c494bfe8d872b183832219a7e14da414d4e3474573671ec19b033be831b915435905925b44947c592959945b4eb7c951c3b9c8cf52530ba23)
  #x00FBBCD0B8D05331FEF6086F22A6CCE4D35724AB7A2F49DD8458D0BFD57A0B8B70F246C17C4468C076874B0DFF7A0336823B19E98BF1CEC05E4BEFFB0591F97713C6)

(deftest ecccdh-secp521r1.4
  (ecccdh-check-secp521r1
    #x000001c8aae94bb10b8ca4f7be577b4fb32bb2381032c4942c24fc2d753e7cc5e47b483389d9f3b956d20ee9001b1eef9f23545f72c5602140046839e963313c3decc864
    #x00000106a14e2ee8ff970aa8ab0c79b97a33bba2958e070b75b94736b77bbe3f777324fa52872771aa88a63a9e8490c3378df4dc760cd14d62be700779dd1a4377943656
    #x0000002366ce3941e0b284b1aa81215d0d3b9778fce23c8cd1e4ed6fa0abf62156c91d4b3eb55999c3471bed275e9e60e5aa9d690d310bfb15c9c5bbd6f5e9eb39682b74
    #x00000098d99dee0816550e84dbfced7e88137fddcf581a725a455021115fe49f8dc3cf233cd9ea0e6f039dc7919da973cdceaca205da39e0bd98c8062536c47f258f44b5
    #x000000cd225c8797371be0c4297d2b457740100c774141d8f214c23b61aa2b6cd4806b9b70722aa4965fb622f42b7391e27e5ec21c5679c5b06b59127372997d421adc1e)
  #x0145CFA38F25943516C96A5FD4BFEBB2F645D10520117AA51971EFF442808A23B4E23C187E639FF928C3725FBD1C0C2AD0D4AEB207BC1A6FB6CB6D467888DC044B3C)

(deftest ecccdh-secp521r1.5
  (ecccdh-check-secp521r1
    #x0000009b0af137c9696c75b7e6df7b73156bb2d45f482e5a4217324f478b10ceb76af09724cf86afa316e7f89918d31d54824a5c33107a483c15c15b96edc661340b1c0e
    #x000000748cdbb875d35f4bccb62abe20e82d32e4c14dc2feb5b87da2d0ccb11c9b6d4b7737b6c46f0dfb4d896e2db92fcf53cdbbae2a404c0babd564ad7adeac6273efa3
    #x000001984acab8d8f173323de0bb60274b228871609373bb22a17287e9dec7495873abc09a8915b54c8455c8e02f654f602e23a2bbd7a9ebb74f3009bd65ecc650814cc0
    #x0000007ae115adaaf041691ab6b7fb8c921f99d8ed32d283d67084e80b9ad9c40c56cd98389fb0a849d9ecf7268c297b6f93406119f40e32b5773ed25a28a9a85c4a7588
    #x000001a28e004e37eeaefe1f4dbb71f1878696141af3a10a9691c4ed93487214643b761fa4b0fbeeb247cf6d3fba7a60697536ad03f49b80a9d1cb079673654977c5fa94)
  #x005C5721E96C273319FD60ECC46B5962F698E974B429F28FE6962F4AC656BE2EB8674C4AAFC037EAB48ECE612953B1E8D861016B6AD0C79805784C67F73ADA96F351)

(deftest ecccdh-secp521r1.6
  (ecccdh-check-secp521r1
    #x000001e48faacee6dec83ffcde944cf6bdf4ce4bae72747888ebafee455b1e91584971efb49127976a52f4142952f7c207ec0265f2b718cf3ead96ea4f62c752e4f7acd3
    #x0000010eb1b4d9172bcc23f4f20cc9560fc54928c3f34ea61c00391dc766c76ed9fa608449377d1e4fadd1236025417330b4b91086704ace3e4e6484c606e2a943478c86
    #x00000149413864069825ee1d0828da9f4a97713005e9bd1adbc3b38c5b946900721a960fe96ad2c1b3a44fe3de9156136d44cb17cbc2415729bb782e16bfe2deb3069e43
    #x0000012588115e6f7f7bdcfdf57f03b169b479758baafdaf569d04135987b2ce6164c02a57685eb5276b5dae6295d3fe90620f38b5535c6d2260c173e61eb888ca920203
    #x000001542c169cf97c2596fe2ddd848a222e367c5f7e6267ebc1bcd9ab5dcf49158f1a48e4af29a897b7e6a82091c2db874d8e7abf0f58064691344154f396dbaed188b6)
  #x01736D9717429B4F412E903FEBE2F9E0FFFD81355D6CE2C06FF3F66A3BE15CEEC6E65E308347593F00D7F33591DA4043C30763D72749F72CDCEEBE825E4B34ECD570)

(deftest ecccdh-secp521r1.7
  (ecccdh-check-secp521r1
    #x000000c29aa223ea8d64b4a1eda27f39d3bc98ea0148dd98c1cbe595f8fd2bfbde119c9e017a50f5d1fc121c08c1cef31b758859556eb3e0e042d8dd6aaac57a05ca61e3
    #x0000001511c848ef60d5419a98d10204db0fe58224124370061bcfa4e9249d50618c56bf3722471b259f38263bb7b280d23caf2a1ee8737f9371cdb2732cdc958369930c
    #x000001d461681ae6d8c49b4c5f4d6016143fb1bd7491573e3ed0e6c48b82e821644f87f82f0e5f08fd16f1f98fa17586200ab02ed8c627b35c3f27617ec5fd92f456203f
    #x00000169491d55bd09049fdf4c2a53a660480fee4c03a0538675d1cd09b5bba78dac48543ef118a1173b3fbf8b20e39ce0e6b890a163c50f9645b3d21d1cbb3b60a6fff4
    #x00000083494b2eba76910fed33c761804515011fab50e3b377abd8a8a045d886d2238d2c268ac1b6ec88bd71b7ba78e2c33c152e4bf7da5d565e4acbecf5e92c7ad662bb)
  #x018F2AE9476C771726A77780208DEDFEFA205488996B18FECC50BFD4C132753F5766B2CD744AFA9918606DE2E016EFFC63622E9029E76DC6E3F0C69F7AECED565C2C)

(deftest ecccdh-secp521r1.8
  (ecccdh-check-secp521r1
    #x00000028692be2bf5c4b48939846fb3d5bce74654bb2646e15f8389e23708a1afadf561511ea0d9957d0b53453819d60fba8f65a18f7b29df021b1bb01cd163293acc3cc
    #x000001cfdc10c799f5c79cb6930a65fba351748e07567993e5e410ef4cacc4cd8a25784991eb4674e41050f930c7190ac812b9245f48a7973b658daf408822fe5b85f668
    #x00000180d9ddfc9af77b9c4a6f02a834db15e535e0b3845b2cce30388301b51cecbe3276307ef439b5c9e6a72dc2d94d879bc395052dbb4a5787d06efb280210fb8be037
    #x0000008415f5bbd0eee387d6c09d0ef8acaf29c66db45d6ba101860ae45d3c60e1e0e3f7247a4626a60fdd404965c3566c79f6449e856ce0bf94619f97da8da24bd2cfb6
    #x000000fdd7c59c58c361bc50a7a5d0d36f723b17c4f2ad2b03c24d42dc50f74a8c465a0afc4683f10fab84652dfe9e928c2626b5456453e1573ff60be1507467d431fbb2)
  #x0105A346988B92ED8C7A25CE4D79D21BC86CFCC7F99C6CD19DBB4A39F48AB943B79E4F0647348DA0B80BD864B85C6B8D92536D6AA544DC7537A00C858F8B66319E25)

(deftest ecccdh-secp521r1.9
  (ecccdh-check-secp521r1
    #x000001194d1ee613f5366cbc44b504d21a0cf6715e209cd358f2dd5f3e71cc0d67d0e964168c42a084ebda746f9863a86bacffc819f1edf1b8c727ccfb3047240a57c435
    #x0000016bd15c8a58d366f7f2b2f298cc87b7485e9ee70d11d12448b8377c0a82c7626f67aff7f97be7a3546bf417eeeddf75a93c130191c84108042ea2fca17fd3f80d14
    #x000001560502d04b74fce1743aab477a9d1eac93e5226981fdb97a7478ce4ce566ff7243931284fad850b0c2bcae0ddd2d97790160c1a2e77c3ed6c95ecc44b89e2637fc
    #x000001c721eea805a5cba29f34ba5758775be0cf6160e6c08723f5ab17bf96a1ff2bd9427961a4f34b07fc0b14ca4b2bf6845debd5a869f124ebfa7aa72fe565050b7f18
    #x000000b6e89eb0e1dcf181236f7c548fd1a8c16b258b52c1a9bfd3fe8f22841b26763265f074c4ccf2d634ae97b701956f67a11006c52d97197d92f585f5748bc2672eeb)
  #x004531B3D2C6CD12F21604C8610E6723DBF4DAF80B5A459D6BA5814397D1C1F7A21D7C114BE964E27376AAEBE3A7BC3D6AF7A7F8C7BEFB611AFE487FF032921F750F)

(deftest ecccdh-secp521r1.10
  (ecccdh-check-secp521r1
    #x000001fd90e3e416e98aa3f2b6afa7f3bf368e451ad9ca5bd54b5b14aee2ed6723dde5181f5085b68169b09fbec721372ccf6b284713f9a6356b8d560a8ff78ca3737c88
    #x000001ebea1b10d3e3b971b7efb69fc878de11c7f472e4e4d384c31b8d6288d8071517acade9b39796c7af5163bcf71aeda777533f382c6cf0a4d9bbb938c85f44b78037
    #x0000016b0e3e19c2996b2cbd1ff64730e7ca90edca1984f9b2951333535e5748baa34a99f61ff4d5f812079e0f01e87789f34efdad8098015ee74a4f846dd190d16dc6e1
    #x000001c35823e440a9363ab98d9fc7a7bc0c0532dc7977a79165599bf1a9cc64c00fb387b42cca365286e8430360bfad3643bc31354eda50dc936c329ecdb60905c40fcb
    #x000000d9e7f433531e44df4f6d514201cbaabb06badd6783e01111726d815531d233c5cdb722893ffbb2027259d594de77438809738120c6f783934f926c3fb69b40c409)
  #x0100C8935969077BAE0BA89EF0DF8161D975EC5870AC811AE7E65CA5394EFBA4F0633D41BF79EA5E5B9496BBD7AAE000B0594BAA82EF8F244E6984AE87AE1ED124B7)

(deftest ecccdh-secp521r1.11
  (ecccdh-check-secp521r1
    #x0000009012ecfdadc85ced630afea534cdc8e9d1ab8be5f3753dcf5f2b09b40eda66fc6858549bc36e6f8df55998cfa9a0703aecf6c42799c245011064f530c09db98369
    #x000000234e32be0a907131d2d128a6477e0caceb86f02479745e0fe245cb332de631c078871160482eeef584e274df7fa412cea3e1e91f71ecba8781d9205d48386341ad
    #x000001cf86455b09b1c005cffba8d76289a3759628c874beea462f51f30bd581e3803134307dedbb771b3334ee15be2e242cd79c3407d2f58935456c6941dd9b6d155a46
    #x000000093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a
    #x000000aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327acaac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf)
  #x017F36AF19303841D13A389D95EC0B801C7F9A679A823146C75C17BC44256E9AD422A4F8B31F14647B2C7D317B933F7C2946C4B8ABD1D56D620FAB1B5FF1A3ADC71F)

(deftest ecccdh-secp521r1.12
  (ecccdh-check-secp521r1
    #x000001b5ff847f8eff20b88cfad42c06e58c3742f2f8f1fdfd64b539ba48c25926926bd5e332b45649c0b184f77255e9d58fe8afa1a6d968e2cb1d4637777120c765c128
    #x000001de3dc9263bc8c4969dc684be0eec54befd9a9f3dba194d8658a789341bf0d78d84da6735227cafaf09351951691197573c8c360a11e5285712b8bbdf5ac91b977c
    #x000000812de58cd095ec2e5a9b247eb3ed41d8bef6aeace194a7a05b65aa5d289fbc9b1770ec84bb6be0c2c64cc37c1d54a7f5d71377a9adbe20f26f6f2b544a821ea831
    #x00000083192ed0b1cb31f75817794937f66ad91cf74552cd510cedb9fd641310422af5d09f221cad249ee814d16dd7ac84ded9eacdc28340fcfc9c0c06abe30a2fc28cd8
    #x0000002212ed868c9ba0fb2c91e2c39ba93996a3e4ebf45f2852d0928c48930e875cc7b428d0e7f3f4d503e5d60c68cb49b13c2480cd486bed9200caddaddfe4ff8e3562)
  #x00062F9FC29AE1A68B2EE0DCF956CBD38C88AE5F645EAA546B00EBE87A7260BF724BE20D34B9D02076655C933D056B21E304C24DDB1DEDF1DD76DE611FC4A2340336)

(deftest ecccdh-secp521r1.13
  (ecccdh-check-secp521r1
    #x0000011a6347d4e801c91923488354cc533e7e35fddf81ff0fb7f56bb0726e0c29ee5dcdc5f394ba54cf57269048aab6e055895c8da24b8b0639a742314390cc04190ed6
    #x000000fe30267f33ba5cdefc25cbb3c9320dad9ccb1d7d376644620ca4fadee5626a3cede25ad254624def727a7048f7145f76162aa98042f9b123b2076f8e8cf59b3fdf
    #x0000001145dc6631953b6e2945e94301d6cbb098fe4b04f7ee9b09411df104dc82d7d79ec46a01ed0f2d3e7db6eb680694bdeb107c1078aec6cabd9ebee3d342fe7e54df
    #x000001a89b636a93e5d2ba6c2292bf23033a84f06a3ac1220ea71e806afbe097a804cc67e9baa514cfb6c12c9194be30212bf7aae7fdf6d376c212f0554e656463ffab7e
    #x00000182efcaf70fc412d336602e014da47256a0b606f2addcce8053bf817ac8656bb4e42f14c8cbf2a68f488ab35dcdf64056271dee1f606a440ba4bd4e5a11b8b8e54f)
  #x0128AB09BFEC5406799E610F772BA17E892249FA8E0E7B18A04B9197034B250B48294F1867FB9641518F92766066A07A8B917B0E76879E1011E51CCBD9F540C54D4F)

(deftest ecccdh-secp521r1.14
  (ecccdh-check-secp521r1
    #x00000022b6d2a22d71dfaa811d2d9f9f31fbed27f2e1f3d239538ddf3e4cc8c39a330266db25b7bc0a9704f17bde7f3592bf5f1f2d4b56013aacc3d8d1bc02f00d3146cc
    #x000000ba38cfbf9fd2518a3f61d43549e7a6a6d28b2be57ffd3e0faceb636b34ed17e044a9f249dae8fc132e937e2d9349cd2ed77bb1049ceb692a2ec5b17ad61502a64c
    #x0000001ec91d3058573fa6c0564a02a1a010160c313bc7c73510dc983e5461682b5be00dbce7e2c682ad73f29ca822cdc111f68fabe33a7b384a648342c3cdb9f050bcdb
    #x0000017200b3f16a68cbaed2bf78ba8cddfb6cffac262bba00fbc25f9dc72a07ce59372904899f364c44cb264c097b647d4412bee3e519892d534d9129f8a28f7500fee7
    #x000000baba8d672a4f4a3b63de48b96f56e18df5d68f7d70d5109833f43770d6732e06b39ad60d93e5b43db8789f1ec0aba47286a39ea584235acea757dbf13d53b58364)
  #x0101E462E9D9159968F6440E956F11DCF2227AE4AEA81667122B6AF9239A291EB5D6CF5A4087F358525FCACFA46BB2DB01A75AF1BA519B2D31DA33EDA87A9D565748)

(deftest ecccdh-secp521r1.15
  (ecccdh-check-secp521r1
    #x0000005bacfff268acf6553c3c583b464ea36a1d35e2b257a5d49eb3419d5a095087c2fb4d15cf5bf5af816d0f3ff7586490ccd3ddc1a98b39ce63749c6288ce0dbdac7d
    #x00000036e488da7581472a9d8e628c58d6ad727311b7e6a3f6ae33a8544f34b09280249020be7196916fafd90e2ec54b66b5468d2361b99b56fa00d7ac37abb8c6f16653
    #x0000011edb9fb8adb6a43f4f5f5fdc1421c9fe04fc8ba46c9b66334e3af927c8befb4307104f299acec4e30f812d9345c9720d19869dbfffd4ca3e7d2713eb5fc3f42615
    #x0000004efd5dbd2f979e3831ce98f82355d6ca14a5757842875882990ab85ab9b7352dd6b9b2f4ea9a1e95c3880d65d1f3602f9ca653dc346fac858658d75626f4d4fb08
    #x00000061cf15dbdaa7f31589c98400373da284506d70c89f074ed262a9e28140796b7236c2eef99016085e71552ff488c72b7339fefb7915c38459cb20ab85aec4e45052)
  #x0141D6A4B719AB67EAF04A92C0A41E2DDA78F4354FB90BDC35202CC7699B9B04D49616F82255DEBF7BBEC045AE58F982A66905FCFAE69D689785E38C868EB4A27E7B)

(deftest ecccdh-secp521r1.16
  (ecccdh-check-secp521r1
    #x0000008e2c93c5423876223a637cad367c8589da69a2d0fc68612f31923ae50219df2452e7cc92615b67f17b57ffd2f52b19154bb40d7715336420fde2e89fee244f59dc
    #x000000fa3b35118d6c422570f724a26f90b2833b19239174cea081c53133f64db60d6940ea1261299c04c1f4587cdb0c4c39616479c1bb0c146799a118032dcf98f899c0
    #x00000069f040229006151fa32b51f679c8816f7c17506b403809dc77cd58a2aec430d94d13b6c916de99f355aa45fcfbc6853d686c71be496a067d24bfaea4818fc51f75
    #x00000129891de0cf3cf82e8c2cf1bf90bb296fe00ab08ca45bb7892e0e227a504fdd05d2381a4448b68adff9c4153c87eacb78330d8bd52515f9f9a0b58e85f446bb4e10
    #x0000009edd679696d3d1d0ef327f200383253f6413683d9e4fcc87bb35f112c2f110098d15e5701d7ceee416291ff5fed85e687f727388b9afe26a4f6feed560b218e6bb)
  #x00345E26E0ABB1AAC12B75F3A9CF41EFE1C336396DFFA4A067A4C2CFEB878C68B2B045FAA4E5B4E6FA4678F5B603C351903B14BF9A6A70C439257199A640890B61D1)

(deftest ecccdh-secp521r1.17
  (ecccdh-check-secp521r1
    #x00000004d49d39d40d8111bf16d28c5936554326b197353eebbcf47545393bc8d3aaf98f14f5be7074bfb38e6cc97b989754074daddb3045f4e4ce745669fdb3ec0d5fa8
    #x0000012ec226d050ce07c79b3df4d0f0891f9f7adf462e8c98dbc1a2a14f5e53a3f5ad894433587cc429a8be9ea1d84fa33b1803690dae04da7218d30026157fc995cf52
    #x0000004837dfbf3426f57b5c793269130abb9a38f618532211931154db4eeb9aede88e57290f842ea0f2ea9a5f74c6203a3920fe4e305f6118f676b154e1d75b9cb5eb88
    #x000001a3c20240e59f5b7a3e17c275d2314ba1741210ad58b71036f8c83cc1f6b0f409dfdd9113e94b67ec39c3291426c23ffcc447054670d2908ff8fe67dc2306034c5c
    #x000001d2825bfd3af8b1e13205780c137fe938f84fde40188e61ea02cead81badfdb425c29f7d7fb0324debadc10bbb93de68f62c35069268283f5265865db57a79f7bf7)
  #x006FE9DE6FB8E672E7FD150FDC5E617FABB0D43906354CCFD224757C7276F7A1010091B17ED072074F8D10A5EC971EB35A5CB7076603B7BC38D432CBC059F80F9488)

(deftest ecccdh-secp521r1.18
  (ecccdh-check-secp521r1
    #x0000011a5d1cc79cd2bf73ea106f0e60a5ace220813b53e27b739864334a07c03367efda7a4619fa6eef3a9746492283b3c445610a023a9cc49bf4591140384fca5c8bb5
    #x000000eb07c7332eedb7d3036059d35f7d2288d4377d5f42337ad3964079fb120ccd4c8bd384b585621055217023acd9a94fcb3b965bfb394675e788ade41a1de73e620c
    #x000000491a835de2e6e7deb7e090f4a11f2c460c0b1f3d5e94ee8d751014dc720784fd3b54500c86ebaef18429f09e8e876d5d1538968a030d7715dde99f0d8f06e29d59
    #x0000007e2d138f2832e345ae8ff65957e40e5ec7163f016bdf6d24a2243daa631d878a4a16783990c722382130f9e51f0c1bd6ff5ac96780e48b68f5dec95f42e6144bb5
    #x000000b0de5c896791f52886b0f09913e26e78dd0b69798fc4df6d95e3ca708ecbcbcce1c1895f5561bbabaae372e9e67e6e1a3be60e19b470cdf673ec1fc393d3426e20)
  #x01E4E759ECEDCE1013BAF73E6FCC0B92451D03BDD50489B78871C333114990C9BA6A9B2FC7B1A2D9A1794C1B60D9279AF6F146F0BBFB0683140403BFA4CCDB524A29)

(deftest ecccdh-secp521r1.19
  (ecccdh-check-secp521r1
    #x0000010c908caf1be74c616b625fc8c1f514446a6aec83b5937141d6afbb0a8c7666a7746fa1f7a6664a2123e8cdf6cd8bf836c56d3c0ebdcc980e43a186f938f3a78ae7
    #x00000031890f4c7abec3f723362285d77d2636f876817db3bbc88b01e773597b969ff6f013ea470c854ab4a7739004eb8cbea69b82ddf36acadd406871798ecb2ac3aa7f
    #x000000d8b429ae3250266b9643c0c765a60dc10155bc2531cf8627296f4978b6640a9e600e19d0037d58503fa80799546a814d7478a550aa90e5ebeb052527faaeae5d08
    #x000000118c36022209b1af8ebad1a12b566fc48744576e1199fe80de1cdf851cdf03e5b9091a8f7e079e83b7f827259b691d0c22ee29d6bdf73ec7bbfd746f2cd97a357d
    #x000000da5ff4904548a342e2e7ba6a1f4ee5f840411a96cf63e6fe622f22c13e614e0a847c11a1ab3f1d12cc850c32e095614ca8f7e2721477b486e9ff40372977c3f65c)
  #x0163C9191D651039A5FE985A0EEA1EBA018A40AB1937FCD2B61220820EE8F2302E9799F6EDFC3F5174F369D672D377EA8954A8D0C8B851E81A56FDA95212A6578F0E)

(deftest ecccdh-secp521r1.20
  (ecccdh-check-secp521r1
    #x000001b37d6b7288de671360425d3e5ac1ccb21815079d8d73431e9b74a6f0e7ae004a357575b11ad66642ce8b775593eba9d98bf25c75ef0b4d3a2098bbc641f59a2b77
    #x000000189a5ee34de7e35aefeaeef9220c18071b4c29a4c3bd9d954458bd3e82a7a34da34cff5579b8101c065b1f2f527cf4581501e28ef5671873e65267733d003520af
    #x000001eb4bc50a7b4d4599d7e3fa773ddb9eb252c9b3422872e544bdf75c7bf60f5166ddc11eb08fa7c30822dabaee373ab468eb2d922e484e2a527fff2ebb804b7d9a37
    #x000001780edff1ca1c03cfbe593edc6c049bcb2860294a92c355489d9afb2e702075ade1c953895a456230a0cde905de4a3f38573dbfcccd67ad6e7e93f0b5581e926a5d
    #x000000a5481962c9162962e7f0ebdec936935d0eaa813e8226d40d7f6119bfd940602380c86721e61db1830f51e139f210000bcec0d8edd39e54d73a9a129f95cd5fa979)
  #x015D613E267A36342E0D125CDAD643D80D97ED0600AFB9E6B9545C9E64A98CC6DA7C5AAA3A8DA0BDD9DD3B97E9788218A80ABAFC106EF065C8F1C4E1119EF58D298B)

(deftest ecccdh-secp521r1.21
  (ecccdh-check-secp521r1
    #x000000f2661ac762f60c5fff23be5d969ccd4ec6f98e4e72618d12bdcdb9b4102162333788c0bae59f91cdfc172c7a1681ee44d96ab2135a6e5f3415ebbcd55165b1afb0
    #x000000a8e25a6902d687b4787cdc94c364ac7cecc5c495483ed363dc0aa95ee2bd739c4c4d46b17006c728b076350d7d7e54c6822f52f47162a25109aaaba690cab696ec
    #x00000168d2f08fe19e4dc9ee7a195b03c9f7fe6676f9f520b6270557504e72ca4394a2c6918625e15ac0c51b8f95cd560123653fb8e8ee6db961e2c4c62cc54e92e2a2a9
    #x0000016dacffa183e5303083a334f765de724ec5ec9402026d4797884a9828a0d321a8cfac74ab737fe20a7d6befcfc73b6a35c1c7b01d373e31abc192d48a4241a35803
    #x0000011e5327cac22d305e7156e559176e19bee7e4f2f59e86f1a9d0b6603b6a7df1069bde6387feb71587b8ffce5b266e1bae86de29378a34e5c74b6724c4d40a719923)
  #x014D6082A3B5CED1AB8CA265A8106F302146C4ACB8C30BB14A4C991E3C82A9731288BDB91E0E85BDA313912D06384FC44F2153FB13506FA9CF43C9AAB5750988C943)

(deftest ecccdh-secp521r1.22
  (ecccdh-check-secp521r1
    #x000000f430ca1261f09681a9282e9e970a9234227b1d5e58d558c3cc6eff44d1bdf53de16ad5ee2b18b92d62fc79586116b0efc15f79340fb7eaf5ce6c44341dcf8dde27
    #x0000006c1d9b5eca87de1fb871a0a32f807c725adccde9b3967453a71347d608f0c030cd09e338cdecbf4a02015bc8a6e8d3e2595fe773ffc2fc4e4a55d0b1a2cc00323b
    #x000001141b2109e7f4981c952aa818a2b9f6f5c41feccdb7a7a45b9b4b672937771b008cae5f934dfe3fed10d383ab1f38769c92ce88d9be5414817ecb073a31ab368ccb
    #x000000a091421d3703e3b341e9f1e7d58f8cf7bdbd1798d001967b801d1cec27e605c580b2387c1cb464f55ce7ac80334102ab03cfb86d88af76c9f4129c01bedd3bbfc4
    #x0000008c9c577a8e6fc446815e9d40baa66025f15dae285f19eb668ee60ae9c98e7ecdbf2b2a68e22928059f67db188007161d3ecf397e0883f0c4eb7eaf7827a62205cc)
  #x0020C00747CB8D492FD497E0FEC54644BF027D418AB686381F109712A99CABE328B9743D2225836F9AD66E5D7FED1DE247E0DA92F60D5B31F9E47672E57F710598F4)

(deftest ecccdh-secp521r1.23
  (ecccdh-check-secp521r1
    #x0000005dc33aeda03c2eb233014ee468dff753b72f73b00991043ea353828ae69d4cd0fadeda7bb278b535d7c57406ff2e6e473a5a4ff98e90f90d6dadd25100e8d85666
    #x000000c825ba307373cec8dd2498eef82e21fd9862168dbfeb83593980ca9f82875333899fe94f137daf1c4189eb502937c3a367ea7951ed8b0f3377fcdf2922021d46a5
    #x0000016b8a2540d5e65493888bc337249e67c0a68774f3e8d81e3b4574a0125165f0bd58b8af9de74b35832539f95c3cd9f1b759408560aa6851ae3ac7555347b0d3b13b
    #x0000004f38816681771289ce0cb83a5e29a1ab06fc91f786994b23708ff08a08a0f675b809ae99e9f9967eb1a49f196057d69e50d6dedb4dd2d9a81c02bdcc8f7f518460
    #x0000009efb244c8b91087de1eed766500f0e81530752d469256ef79f6b965d8a2232a0c2dbc4e8e1d09214bab38485be6e357c4200d073b52f04e4a16fc6f5247187aecb)
  #x00C2BFAFCD7FBD3E2FD1C750FDEA61E70BD4787A7E68468C574EE99EBC47EEDEF064E8944A73BCB7913DBAB5D93DCA660D216C553622362794F7A2ACC71022BDB16F)

(deftest ecccdh-secp521r1.24
  (ecccdh-check-secp521r1
    #x000000df14b1f1432a7b0fb053965fd8643afee26b2451ecb6a8a53a655d5fbe16e4c64ce8647225eb11e7fdcb23627471dffc5c2523bd2ae89957cba3a57a23933e5a78
    #x0000004e8583bbbb2ecd93f0714c332dff5ab3bc6396e62f3c560229664329baa5138c3bb1c36428abd4e23d17fcb7a2cfcc224b2e734c8941f6f121722d7b6b94154576
    #x000001cf0874f204b0363f020864672fadbf87c8811eb147758b254b74b14fae742159f0f671a018212bbf25b8519e126d4cad778cfff50d288fd39ceb0cac635b175ec0
    #x000001a32099b02c0bd85371f60b0dd20890e6c7af048c8179890fda308b359dbbc2b7a832bb8c6526c4af99a7ea3f0b3cb96ae1eb7684132795c478ad6f962e4a6f446d
    #x0000017627357b39e9d7632a1370b3e93c1afb5c851b910eb4ead0c9d387df67cde85003e0e427552f1cd09059aad0262e235cce5fba8cedc4fdc1463da76dcd4b6d1a46)
  #x01AAF24E5D47E4080C18C55EA35581CD8DA30F1A079565045D2008D51B12D0ABB4411CDA7A0785B15D149ED301A3697062F42DA237AA7F07E0AF3FD00EB1800D9C41)

;;  secp256r1
(deftest secp256r1-dhweierstrass-init.1
  (with-elliptic-secp256r1
    (diffie-hellman-p
      (dhweierstrass-init)))
  t)

(deftest secp256r1-dhweierstrass-send.1
  (with-elliptic-secp256r1
    (let ((s (dhweierstrass-init)))
      (multiple-value-bind (x y) (dhweierstrass-send s)
        (values (vectorp x)
                (vectorp y)))))
  t t)

(deftest secp256r1-dhweierstrass-send.2
  (with-elliptic-secp256r1
    (let ((s (dhweierstrass-init)))
      (multiple-value-bind (x y) (dhweierstrass-send s)
        (values (length x)
                (length y)))))
  32 32)

(deftest secp256r1-dhweierstrass-receive.1
  (with-elliptic-secp256r1
    (let* ((s (dhweierstrass-init))
           (z (dhweierstrass-init))
           (u (diffie-hellman-a z))
           (a (affine u))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (point3-p
        (dhweierstrass-reveice s x1 y1))))
  t)

(deftest secp256r1-dhweierstrass-receive.2
  (with-elliptic-secp256r1
    (let* ((s (dhweierstrass-init))
           (x1 (encode3-vector 1))
           (y1 (encode3-vector 2)))
      (dhweierstrass-reveice s x1 y1)))
  nil)

(deftest secp256r1-dhweierstrass-shared.1
  (with-elliptic-secp256r1
    (let ((s (dhweierstrass-init)))
      (dhweierstrass-shared s)))
  nil)

(deftest secp256r1-dhweierstrass-shared.2
  (with-elliptic-secp256r1
    (let* ((s (dhweierstrass-init))
           (z (dhweierstrass-init))
           (u (diffie-hellman-a z))
           (a (affine u))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhweierstrass-reveice s x1 y1)
      (point3-p
        (dhweierstrass-shared s))))
  t)

(deftest secp256r1-dhweierstrass-output.1
  (with-elliptic-secp256r1
    (let ((s (dhweierstrass-init)))
      (dhweierstrass-output s)))
  nil)

(deftest secp256r1-dhweierstrass-output.2
  (with-elliptic-secp256r1
    (let* ((s (dhweierstrass-init))
           (z (dhweierstrass-init))
           (u (diffie-hellman-a z))
           (a (affine u))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhweierstrass-reveice s x1 y1)
      (dhweierstrass-shared s)
      (multiple-value-bind (a b) (dhweierstrass-output s)
        (values
          (vectorp a) (vectorp b)
          (length a) (length b)))))
  t t 32 32)

(deftest secp256r1-diffie-hellman.1
  (with-elliptic-secp256r1
    (let* ((a (dhweierstrass-init))
           (b (dhweierstrass-init)))
      (multiple-value-bind (x y) (dhweierstrass-send a)
        (dhweierstrass-reveice b x y))
      (multiple-value-bind (x y) (dhweierstrass-send b)
        (dhweierstrass-reveice a x y))
      (dhweierstrass-shared a)
      (dhweierstrass-shared b)
      (multiple-value-bind (x1 y1) (dhweierstrass-output a)
        (multiple-value-bind (x2 y2) (dhweierstrass-output b)
          (and (equalp x1 x2)
               (equalp y1 y2))))))
  t)

;;  secp384r1
(deftest secp384r1-dhweierstrass-init.1
  (with-elliptic-secp384r1
    (diffie-hellman-p
      (dhweierstrass-init)))
  t)

(deftest secp384r1-dhweierstrass-send.1
  (with-elliptic-secp384r1
    (let ((s (dhweierstrass-init)))
      (multiple-value-bind (x y) (dhweierstrass-send s)
        (values (vectorp x)
                (vectorp y)))))
  t t)

(deftest secp384r1-dhweierstrass-send.2
  (with-elliptic-secp384r1
    (let ((s (dhweierstrass-init)))
      (multiple-value-bind (x y) (dhweierstrass-send s)
        (values (length x)
                (length y)))))
  48 48)

(deftest secp384r1-dhweierstrass-receive.1
  (with-elliptic-secp384r1
    (let* ((s (dhweierstrass-init))
           (z (dhweierstrass-init))
           (u (diffie-hellman-a z))
           (a (affine u))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (point3-p
        (dhweierstrass-reveice s x1 y1))))
  t)

(deftest secp384r1-dhweierstrass-receive.2
  (with-elliptic-secp384r1
    (let* ((s (dhweierstrass-init))
           (x1 (encode3-vector 1))
           (y1 (encode3-vector 2)))
      (dhweierstrass-reveice s x1 y1)))
  nil)

(deftest secp384r1-dhweierstrass-shared.1
  (with-elliptic-secp384r1
    (let ((s (dhweierstrass-init)))
      (dhweierstrass-shared s)))
  nil)

(deftest secp384r1-dhweierstrass-shared.2
  (with-elliptic-secp384r1
    (let* ((s (dhweierstrass-init))
           (z (dhweierstrass-init))
           (u (diffie-hellman-a z))
           (a (affine u))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhweierstrass-reveice s x1 y1)
      (point3-p
        (dhweierstrass-shared s))))
  t)

(deftest secp384r1-dhweierstrass-output.1
  (with-elliptic-secp384r1
    (let ((s (dhweierstrass-init)))
      (dhweierstrass-output s)))
  nil)

(deftest secp384r1-dhweierstrass-output.2
  (with-elliptic-secp384r1
    (let* ((s (dhweierstrass-init))
           (z (dhweierstrass-init))
           (u (diffie-hellman-a z))
           (a (affine u))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhweierstrass-reveice s x1 y1)
      (dhweierstrass-shared s)
      (multiple-value-bind (a b) (dhweierstrass-output s)
        (values
          (vectorp a) (vectorp b)
          (length a) (length b)))))
  t t 48 48)

(deftest secp384r1-diffie-hellman.1
  (with-elliptic-secp384r1
    (let* ((a (dhweierstrass-init))
           (b (dhweierstrass-init)))
      (multiple-value-bind (x y) (dhweierstrass-send a)
        (dhweierstrass-reveice b x y))
      (multiple-value-bind (x y) (dhweierstrass-send b)
        (dhweierstrass-reveice a x y))
      (dhweierstrass-shared a)
      (dhweierstrass-shared b)
      (multiple-value-bind (x1 y1) (dhweierstrass-output a)
        (multiple-value-bind (x2 y2) (dhweierstrass-output b)
          (and (equalp x1 x2)
               (equalp y1 y2))))))
  t)

;;  secp521r1
(deftest secp521r1-dhweierstrass-init.1
  (with-elliptic-secp521r1
    (diffie-hellman-p
      (dhweierstrass-init)))
  t)

(deftest secp521r1-dhweierstrass-send.1
  (with-elliptic-secp521r1
    (let ((s (dhweierstrass-init)))
      (multiple-value-bind (x y) (dhweierstrass-send s)
        (values (vectorp x)
                (vectorp y)))))
  t t)

(deftest secp521r1-dhweierstrass-send.2
  (with-elliptic-secp521r1
    (let ((s (dhweierstrass-init)))
      (multiple-value-bind (x y) (dhweierstrass-send s)
        (values (length x)
                (length y)))))
  66 66)

(deftest secp521r1-dhweierstrass-receive.1
  (with-elliptic-secp521r1
    (let* ((s (dhweierstrass-init))
           (z (dhweierstrass-init))
           (u (diffie-hellman-a z))
           (a (affine u))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (point3-p
        (dhweierstrass-reveice s x1 y1))))
  t)

(deftest secp521r1-dhweierstrass-receive.2
  (with-elliptic-secp521r1
    (let* ((s (dhweierstrass-init))
           (x1 (encode3-vector 1))
           (y1 (encode3-vector 2)))
      (dhweierstrass-reveice s x1 y1)))
  nil)

(deftest secp521r1-dhweierstrass-shared.1
  (with-elliptic-secp521r1
    (let ((s (dhweierstrass-init)))
      (dhweierstrass-shared s)))
  nil)

(deftest secp521r1-dhweierstrass-shared.2
  (with-elliptic-secp521r1
    (let* ((s (dhweierstrass-init))
           (z (dhweierstrass-init))
           (u (diffie-hellman-a z))
           (a (affine u))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhweierstrass-reveice s x1 y1)
      (point3-p
        (dhweierstrass-shared s))))
  t)

(deftest secp521r1-dhweierstrass-output.1
  (with-elliptic-secp521r1
    (let ((s (dhweierstrass-init)))
      (dhweierstrass-output s)))
  nil)

(deftest secp521r1-dhweierstrass-output.2
  (with-elliptic-secp521r1
    (let* ((s (dhweierstrass-init))
           (z (dhweierstrass-init))
           (u (diffie-hellman-a z))
           (a (affine u))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhweierstrass-reveice s x1 y1)
      (dhweierstrass-shared s)
      (multiple-value-bind (a b) (dhweierstrass-output s)
        (values
          (vectorp a) (vectorp b)
          (length a) (length b)))))
  t t 66 66)

(deftest secp521r1-diffie-hellman.1
  (with-elliptic-secp521r1
    (let* ((a (dhweierstrass-init))
           (b (dhweierstrass-init)))
      (multiple-value-bind (x y) (dhweierstrass-send a)
        (dhweierstrass-reveice b x y))
      (multiple-value-bind (x y) (dhweierstrass-send b)
        (dhweierstrass-reveice a x y))
      (dhweierstrass-shared a)
      (dhweierstrass-shared b)
      (multiple-value-bind (x1 y1) (dhweierstrass-output a)
        (multiple-value-bind (x2 y2) (dhweierstrass-output b)
          (and (equalp x1 x2)
               (equalp y1 y2))))))
  t)

;;  curve25519
(deftest curve25519-dhmontgomery-init.1
  (with-elliptic-curve25519
    (diffie-hellman-p
      (dhmontgomery-init)))
  t)

(deftest curve25519-dhmontgomery-send.1
  (with-elliptic-curve25519
    (let ((s (dhmontgomery-init)))
      (multiple-value-bind (x y) (dhmontgomery-send s)
        (values (vectorp x)
                (vectorp y)))))
  t t)

(deftest curve25519-dhmontgomery-send.2
  (with-elliptic-curve25519
    (let ((s (dhmontgomery-init)))
      (multiple-value-bind (x y) (dhmontgomery-send s)
        (values (length x)
                (length y)))))
  32 32)

(deftest curve25519-dhmontgomery-receive.1
  (with-elliptic-curve25519
    (let* ((s (dhmontgomery-init))
           (z (dhmontgomery-init))
           (a (diffie-hellman-a z))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (point2-p
        (dhmontgomery-reveice s x1 y1))))
  t)

(deftest curve25519-dhmontgomery-receive.2
  (with-elliptic-curve25519
    (let* ((s (dhmontgomery-init))
           (x1 (encode3-vector 1))
           (y1 (encode3-vector 2)))
      (dhmontgomery-reveice s x1 y1)))
  nil)

(deftest curve25519-dhmontgomery-shared.1
  (with-elliptic-curve25519
    (let ((s (dhmontgomery-init)))
      (dhmontgomery-shared s)))
  nil)

(deftest curve25519-dhmontgomery-shared.2
  (with-elliptic-curve25519
    (let* ((s (dhmontgomery-init))
           (z (dhmontgomery-init))
           (a (diffie-hellman-a z))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhmontgomery-reveice s x1 y1)
      (point2-p
        (dhmontgomery-shared s))))
  t)

(deftest curve25519-dhmontgomery-output.1
  (with-elliptic-curve25519
    (let ((s (dhmontgomery-init)))
      (dhmontgomery-output s)))
  nil)

(deftest curve25519-dhmontgomery-output.2
  (with-elliptic-curve25519
    (let* ((s (dhmontgomery-init))
           (z (dhmontgomery-init))
           (a (diffie-hellman-a z))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhmontgomery-reveice s x1 y1)
      (dhmontgomery-shared s)
      (multiple-value-bind (a b) (dhmontgomery-output s)
        (values
          (vectorp a) (vectorp b)
          (length a) (length b)
          ))))
  t t 32 32)

(deftest curve25519-diffie-hellman.1
  (with-elliptic-curve25519
    (let* ((a (dhmontgomery-init))
           (b (dhmontgomery-init)))
      (multiple-value-bind (x y) (dhmontgomery-send a)
        (dhmontgomery-reveice b x y))
      (multiple-value-bind (x y) (dhmontgomery-send b)
        (dhmontgomery-reveice a x y))
      (dhmontgomery-shared a)
      (dhmontgomery-shared b)
      (multiple-value-bind (x1 y1) (dhmontgomery-output a)
        (multiple-value-bind (x2 y2) (dhmontgomery-output b)
          (and (equalp x1 x2)
               (equalp y1 y2))))))
  t)

;;  curve448
(deftest curve448-dhmontgomery-init.1
  (with-elliptic-curve448
    (diffie-hellman-p
      (dhmontgomery-init)))
  t)

(deftest curve448-dhmontgomery-send.1
  (with-elliptic-curve448
    (let ((s (dhmontgomery-init)))
      (multiple-value-bind (x y) (dhmontgomery-send s)
        (values (vectorp x)
                (vectorp y)))))
  t t)

(deftest curve448-dhmontgomery-send.2
  (with-elliptic-curve448
    (let ((s (dhmontgomery-init)))
      (multiple-value-bind (x y) (dhmontgomery-send s)
        (values (length x)
                (length y)))))
  56 56)

(deftest curve448-dhmontgomery-receive.1
  (with-elliptic-curve448
    (let* ((s (dhmontgomery-init))
           (z (dhmontgomery-init))
           (a (diffie-hellman-a z))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (point2-p
        (dhmontgomery-reveice s x1 y1))))
  t)

(deftest curve448-dhmontgomery-receive.2
  (with-elliptic-curve448
    (let* ((s (dhmontgomery-init))
           (x1 (encode3-vector 1))
           (y1 (encode3-vector 2)))
      (dhmontgomery-reveice s x1 y1)))
  nil)

(deftest curve448-dhmontgomery-shared.1
  (with-elliptic-curve448
    (let ((s (dhmontgomery-init)))
      (dhmontgomery-shared s)))
  nil)

(deftest curve448-dhmontgomery-shared.2
  (with-elliptic-curve448
    (let* ((s (dhmontgomery-init))
           (z (dhmontgomery-init))
           (a (diffie-hellman-a z))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhmontgomery-reveice s x1 y1)
      (point2-p
        (dhmontgomery-shared s))))
  t)

(deftest curve448-dhmontgomery-output.1
  (with-elliptic-curve448
    (let ((s (dhmontgomery-init)))
      (dhmontgomery-output s)))
  nil)

(deftest curve448-dhmontgomery-output.2
  (with-elliptic-curve448
    (let* ((s (dhmontgomery-init))
           (z (dhmontgomery-init))
           (a (diffie-hellman-a z))
           (x (point2-x a))
           (y (point2-y a))
           (x1 (encode3-vector x))
           (y1 (encode3-vector y)))
      (dhmontgomery-reveice s x1 y1)
      (dhmontgomery-shared s)
      (multiple-value-bind (a b) (dhmontgomery-output s)
        (values
          (vectorp a) (vectorp b)
          (length a) (length b)
          ))))
  t t 56 56)

(deftest curve448-diffie-hellman.1
  (with-elliptic-curve448
    (let* ((a (dhmontgomery-init))
           (b (dhmontgomery-init)))
      (multiple-value-bind (x y) (dhmontgomery-send a)
        (dhmontgomery-reveice b x y))
      (multiple-value-bind (x y) (dhmontgomery-send b)
        (dhmontgomery-reveice a x y))
      (dhmontgomery-shared a)
      (dhmontgomery-shared b)
      (multiple-value-bind (x1 y1) (dhmontgomery-output a)
        (multiple-value-bind (x2 y2) (dhmontgomery-output b)
          (and (equalp x1 x2)
               (equalp y1 y2))))))
  t)



;;
;;  main
;;
(let ((*random-state* (make-random-state t)))
  (do-tests))

