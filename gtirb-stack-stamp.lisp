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
  (:use :gt :gtirb :capstone/clos :keystone/clos :stefil)
  (:import-from :cl-intbytes :int->octets :octets->uint)
  (:shadow :version :size :architecture :mode :symbol :address :bytes)
  (:export :gtirb-stack-stamp))
(in-package :gtirb-stack-stamp/gtirb-stack-stamp)
(in-readtable :curry-compose-reader-macros)


;;; Implementation
(defun stamp-value (function)
  "Just hash the function itself to get a deterministic stamp value."
  (sxhash function))

(defvar *cs* (make-instance 'capstone-engine :architecture :x86 :mode :64)
  "Capstone engine instance.")
(defvar *ks* (make-instance 'keystone-engine :architecture :x86 :mode :64)
  "Keystone engine instance.")
(set-option *ks* :syntax :syntax-att)

(defgeneric stack-stamp (object)
  (:documentation "Apply the stack-stamp transformation to OBJECT.")
  (:method ((obj gtirb)) (mapc #'stack-stamp (modules obj)))
  (:method ((obj module)) (mapc #'stack-stamp (functions obj)))
  (:method ((obj func))
    (unless (exits obj)
      (warn "Skipping function without exits: ~s" obj)
      (return-from stack-stamp))
    (unless (entries obj)
      (warn "Skipping function without entries: ~s" obj)
      (return-from stack-stamp))
    (let* ((key (int->octets (stamp-value obj) 8))
           (stamp-bytes (asm *ks* (format nil "xorl $0x~x,(%rsp); ~
                                               xorl $0x~x,4(%rsp);"
                                          (octets->uint (subseq key 0 4) 4)
                                          (octets->uint (subseq key 4) 4)))))
      (mapc (lambda (entry-block)
              (setf (gtirb:bytes entry-block)
                    (concatenate 'vector
                                 stamp-bytes (gtirb:bytes entry-block))))
            (entries obj))
      (mapc (lambda (return-block)
              (let ((bytes (gtirb:bytes return-block)))
                (if-let ((return-position (position-if [{eql :ret} #'mnemonic]
                                                       (disasm *cs* bytes))))
                  (setf (gtirb:bytes return-block)
                        (concatenate 'vector
                                     (subseq bytes 0 return-position)
                                     stamp-bytes
                                     (subseq bytes return-position))))))
            (returns obj)))))


;;;; Helpers
(defgeneric instructions (object)
  (:documentation "Return decoded instructions for OBJECT.")
  (:method ((obj gtirb-byte-block)) (disasm *cs* (gtirb:bytes obj))))


;;;; Main test suite.
(defsuite test)
(in-suite test)

(defvar *hello*)

(defvar *base-dir* (nest (make-pathname :directory)
                         (pathname-directory)
                         #.(or *compile-file-truename*
                               *load-truename*
                               *default-pathname-defaults*)))

(defixture hello
  (:setup (setf *hello* (read-gtirb (merge-pathnames "tests/hello.v1.gtirb"
                                                     *base-dir*))))
  (:teardown (setf *hello* nil)))

(deftest stack-stamp-hello ()
  (with-fixture hello
    (stack-stamp *hello*)))
