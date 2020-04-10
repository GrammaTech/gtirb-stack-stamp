;;; Copyright (C) 2020 GrammaTech, Inc.
;;;
;;; This code is licensed under the MIT license. See the LICENSE file in
;;; the project root for license terms.
;;;
;;; This project is sponsored by the Office of Naval Research, One Liberty
;;; Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
;;; N68335-17-C-0700.  The content of the information does not necessarily
;;; reflect the position or policy of the Government and no official
;;; endorsement should be inferred.
(defpackage :gtirb-stack-stamp/gtirb-stack-stamp
  (:nicknames :gtirb-stack-stamp)
  (:use :gt :gtirb :gtirb-functions :gtirb-capstone :stefil)
  (:shadowing-import-from :gt :size)
  (:import-from :cl-intbytes :int->octets :octets->uint)
  (:import-from :asdf/system :system-relative-pathname)
  (:shadow :version :architecture :mode :symbol)
  (:export :gtirb-stack-stamp))
(in-package :gtirb-stack-stamp/gtirb-stack-stamp)
(in-readtable :curry-compose-reader-macros)
(defmethod size ((obj gtirb-node)) (gtirb:size obj))


;;; Implementation
(defgeneric stack-stamp (object)
  (:documentation "Apply the stack-stamp transformation.")
  (:method ((obj gtirb))
    (set-syntax obj :syntax-att)
    (mapc #'stack-stamp (modules obj)))
  (:method ((obj module)) (mapc #'stack-stamp (functions obj)))
  (:method ((obj func))
    (unless (exits obj)
      (warn "Skipping function without exits: ~s" obj)
      (return-from stack-stamp))
    (unless (entries obj)
      (warn "Skipping function without entries: ~s" obj)
      (return-from stack-stamp))
    (let* ((key (int->octets (sxhash obj) 8))
           (stamp-bytes (asm obj (format nil "xorl $0x~x,(%rsp); ~
                                              xorl $0x~x,4(%rsp);"
                                         (octets->uint (subseq key 0 4) 4)
                                         (octets->uint (subseq key 4) 4)))))
      (mapc (lambda (entry-block) (setf (bytes entry-block 0 0) stamp-bytes))
            (entries obj))
      (mapc
       (lambda (ret-block)
         (if-let ((ret-position (position-if [{eql :ret} #'mnemonic]
                                             (instructions ret-block))))
           (setf (bytes ret-block ret-position ret-position) stamp-bytes)))
       (returns obj)))))

(defmethod stack-stamp :around ((obj gtirb-node)) (call-next-method) obj)


;;;; Main test suite.
(defsuite test)
(in-suite test)

(defvar *hello*)

(defixture hello
  (:setup (setf *hello* (read-gtirb
                         (system-relative-pathname "gtirb-stack-stamp"
                                                   "tests/hello.v1.gtirb"))))
  (:teardown (setf *hello* nil)))

(deftest stack-stamp-hello ()
  (nest
   (with-fixture hello)
   (flet ((symbolic-expressions (it)
            (nest (mappend [#'hash-table-values #'symbolic-expressions])
                  (mappend #'byte-intervals) (mappend #'sections)
                  (modules it)))
          (interval-bytes (it)
            (nest (apply #'concatenate 'vector)
                  (mapcar #'bytes)
                  (mappend #'byte-intervals) (mappend #'sections)
                  (modules it)))
          (block-bytes (it)
            (nest (apply #'concatenate 'vector)
                  (mapcar #'bytes) (mappend #'blocks)
                  (mappend #'byte-intervals) (mappend #'sections)
                  (modules it)))))
   (let ((original-symbolic-expressions (symbolic-expressions *hello*))
         (original-interval-bytes (interval-bytes *hello*))
         (original-bytes (block-bytes *hello*)))
     (is (typep (stack-stamp *hello*) 'gtirb))
     (let ((new-symbolic-expressions (symbolic-expressions *hello*)))
       ;; Should not have fewer symbolic expressions when we're only
       ;; inserting (not removing) instructions (and therefore bytes).
       (is (= (length original-symbolic-expressions)
              (length new-symbolic-expressions)))
       ;; In fact we should have exactly the same instructions.
       (is (= (length original-symbolic-expressions)
              (length new-symbolic-expressions))))
     (let ((new-bytes (block-bytes *hello*)))
       ;; We should have more bytes (with the new stamping instructions).
       (is (< (length original-interval-bytes)
              (length (interval-bytes *hello*))))
       (is (< (length original-bytes) (length new-bytes)))))))
