// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package imagevector_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/yaml"

	. "github.com/gardener/gardener/pkg/utils/imagevector"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
)

var _ = Describe("validation", func() {
	var (
		imageVector           func(string, *string, *string, *string, string, string) ImageVector
		componentImageVectors func(string, ImageVector) ComponentImageVectors
	)

	BeforeEach(func() {
		imageVector = func(name string, ref, repository, tag *string, runtimeVersion, targetVersion string) ImageVector {
			return ImageVector{
				{
					Name:           name,
					Ref:            ref,
					Repository:     repository,
					Tag:            tag,
					RuntimeVersion: new(runtimeVersion),
					TargetVersion:  new(targetVersion),
				},
			}
		}

		componentImageVectors = func(name string, imageVector ImageVector) ComponentImageVectors {
			vector := struct {
				Images ImageVector `json:"images" yaml:"images"`
			}{
				Images: imageVector,
			}

			buf, err := yaml.Marshal(vector)
			Expect(err).NotTo(HaveOccurred())

			return ComponentImageVectors{
				name: string(buf),
			}
		}
	})

	Describe("#ValidateImageVector", func() {
		It("should allow valid image vectors", func() {
			errorList := ValidateImageVector(imageVector("test-image1", nil, new("test-repo"), new("test-tag"), ">= 1.6, < 1.8", ">= 1.8"), field.NewPath("images"))

			Expect(errorList).To(BeEmpty())
		})

		It("should forbid invalid image vectors", func() {
			errorList := ValidateImageVector(imageVector("", nil, nil, new(""), "", "!@#"), field.NewPath("images"))

			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("images[0].name"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("images[0].ref/repository"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("images[0].tag"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("images[0].runtimeVersion"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("images[0].targetVersion"),
				})),
			))
		})

		It("should forbid empty ref", func() {
			Expect(ValidateImageVector(imageVector("foo", new(""), nil, nil, ">= 1.6", "< 1.8"), field.NewPath("images"))).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("images[0].ref"),
					"Detail": Equal("ref must not be empty if specified"),
				})),
			))
		})

		It("should forbid empty repository", func() {
			Expect(ValidateImageVector(imageVector("foo", nil, new(""), nil, ">= 1.6", "< 1.8"), field.NewPath("images"))).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("images[0].repository"),
					"Detail": Equal("repository must not be empty if specified"),
				})),
			))
		})

		It("should forbid specifying repository/tag when ref is set", func() {
			Expect(ValidateImageVector(imageVector("foo", new("ref"), new("repo"), new("tag"), ">= 1.6", "< 1.8"), field.NewPath("images"))).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeForbidden),
					"Field":  Equal("images[0].repository"),
					"Detail": Equal("cannot specify repository when ref is set"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeForbidden),
					"Field":  Equal("images[0].tag"),
					"Detail": Equal("cannot specify tag when ref is set"),
				})),
			))
		})
	})

	Describe("#ValidateComponentImageVectors", func() {
		It("should allow valid component image vectors", func() {
			errorList := ValidateComponentImageVectors(componentImageVectors("test-component1", imageVector("test-image1", nil, new("test-repo"), new("test-tag"), ">= 1.6, < 1.8", ">= 1.8")), field.NewPath("components"))

			Expect(errorList).To(BeEmpty())
		})

		It("should forbid invalid component image vectors", func() {
			errorList := ValidateComponentImageVectors(componentImageVectors("", ImageVector{{}}), field.NewPath("components"))

			Expect(errorList).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("components[].name"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("components[].imageVectorOverwrite"),
				})),
			))
		})
	})

	Describe("#ValidateCABundle", func() {
		var (
			fldPath      *field.Path
			validCertPEM string
		)

		BeforeEach(func() {
			fldPath = field.NewPath("caBundle")

			ca, err := (&secretsutils.CertificateSecretConfig{
				Name:       "test-ca",
				CommonName: "TestCA",
				CertType:   secretsutils.CACert,
			}).GenerateCertificate()
			Expect(err).NotTo(HaveOccurred())
			validCertPEM = string(ca.SecretData()[secretsutils.DataKeyCertificateCA])
		})

		It("should allow nil", func() {
			Expect(ValidateCABundle(nil, fldPath)).To(BeEmpty())
		})

		It("should forbid both secretRef and inline set", func() {
			errs := ValidateCABundle(&CABundle{
				SecretRef: &corev1.LocalObjectReference{Name: "my-secret"},
				Inline:    new(validCertPEM),
			}, fldPath)
			Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeForbidden),
				"Field": Equal("caBundle"),
			}))))
		})

		It("should forbid neither secretRef nor inline set", func() {
			errs := ValidateCABundle(&CABundle{}, fldPath)
			Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeRequired),
				"Field": Equal("caBundle"),
			}))))
		})

		It("should forbid secretRef with empty name", func() {
			errs := ValidateCABundle(&CABundle{SecretRef: &corev1.LocalObjectReference{Name: ""}}, fldPath)
			Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeRequired),
				"Field": Equal("caBundle.secretRef.name"),
			}))))
		})

		It("should allow a valid secretRef", func() {
			Expect(ValidateCABundle(&CABundle{SecretRef: &corev1.LocalObjectReference{Name: "my-ca-secret"}}, fldPath)).To(BeEmpty())
		})

		It("should forbid empty inline", func() {
			errs := ValidateCABundle(&CABundle{Inline: new("")}, fldPath)
			Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("caBundle.inline"),
			}))))
		})

		It("should forbid non-PEM inline", func() {
			errs := ValidateCABundle(&CABundle{Inline: new("not-a-certificate")}, fldPath)
			Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("caBundle.inline"),
			}))))
		})

		It("should allow a valid inline PEM", func() {
			Expect(ValidateCABundle(&CABundle{Inline: new(validCertPEM)}, fldPath)).To(BeEmpty())
		})
	})
})
