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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	. "github.com/gardener/gardener/pkg/utils/imagevector"
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
					RuntimeVersion: ptr.To(runtimeVersion),
					TargetVersion:  ptr.To(targetVersion),
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
			errorList := ValidateImageVector(imageVector("test-image1", nil, ptr.To("test-repo"), ptr.To("test-tag"), ">= 1.6, < 1.8", ">= 1.8"), field.NewPath("images"))

			Expect(errorList).To(BeEmpty())
		})

		It("should forbid invalid image vectors", func() {
			errorList := ValidateImageVector(imageVector("", nil, nil, ptr.To(""), "", "!@#"), field.NewPath("images"))

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
			Expect(ValidateImageVector(imageVector("foo", ptr.To(""), nil, nil, ">= 1.6", "< 1.8"), field.NewPath("images"))).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("images[0].ref"),
					"Detail": Equal("ref must not be empty if specified"),
				})),
			))
		})

		It("should forbid empty repository", func() {
			Expect(ValidateImageVector(imageVector("foo", nil, ptr.To(""), nil, ">= 1.6", "< 1.8"), field.NewPath("images"))).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInvalid),
					"Field":  Equal("images[0].repository"),
					"Detail": Equal("repository must not be empty if specified"),
				})),
			))
		})

		It("should forbid specifying repository/tag when ref is set", func() {
			Expect(ValidateImageVector(imageVector("foo", ptr.To("ref"), ptr.To("repo"), ptr.To("tag"), ">= 1.6", "< 1.8"), field.NewPath("images"))).To(ConsistOf(
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
			errorList := ValidateComponentImageVectors(componentImageVectors("test-component1", imageVector("test-image1", nil, ptr.To("test-repo"), ptr.To("test-tag"), ">= 1.6, < 1.8", ">= 1.8")), field.NewPath("components"))

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
		// spellchecker:off
		const validCertPEM = `-----BEGIN CERTIFICATE-----
MIIDAjCCAeqgAwIBAgIRALm+TCqth9laBtLixvzY0QMwDQYJKoZIhvcNAQELBQAw
GDEWMBQGA1UEAxMNa3ViZXJuZXRlcy1jYTAeFw0yMTA0MjAxMDA5NTlaFw0zMTA0
MjAxMDA5NTlaMCoxKDAmBgNVBAMTH2dhcmRlbmVyLmNsb3VkOnN5c3RlbTpzY2hl
ZHVsZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9evZPyHGr8ANc
2mKA+hqb5glTv+PXpRD0ms/ZrRmho5IIIFjg3Lg7Zvlj5tgQd7lYhRYDsLudioDj
tm2cc0txNIPpcfly77imfSx1PzGRpHvqZCJMkMBSDsFgEUNp1+Fe6uBydrInC3RF
1AVu0m+yXmrQTuVi8R6Yw7tBA+Ri1Lo6IMUB5o247I1MnDoT3SOjhYEzUAsoBRVC
TE4MG6HY8CxCXnJo4E3Kg86rrEjFOUXDqQsf9MMaLOEHONwGGL/9BOq0nx6CHm06
eQP1w5QgtCSo/0l2K8MynBWdUEPXj/zYTkSzgAlF/2ry7cXxG/r6z5KIGLQ1Pmy2
GFJQFgTtAgMBAAGjNTAzMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEF
BQcDAjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAD8QontES/613+
GIiqTQJIm9FVg+/Co7NRfikeRb4xaakhQih33U4yts4GtRcIu1+dpGQa//M/h2ZA
C6tqNevOV5pamSgxf+BUi8Cy/Aw7tstPmdwUrhPJ++aHdxrVor+gZAWse4MDx2th
eVr+HZ2/OqQWR6GCJvBurvHbKAL/OE6+dOKs/m0RTBguA5mEupEMiVpc8wugtY3P
VwrlW5w5FBRjxqIfVvTPyijJeA3DjooKMNgCq98ghZfaZPLvYAb5RDi4mhJnQwuc
Y4ud3vcGwEsGQx5P8oJ/wanM/Fp4h1QTda1Fim3QkeeVKYu1r4DEeU4ROP7j3hUB
VusoisJW
-----END CERTIFICATE-----`
		// spellchecker:on

		var fldPath *field.Path
		BeforeEach(func() { fldPath = field.NewPath("caBundle") })

		It("should allow nil", func() {
			Expect(ValidateCABundle(nil, fldPath)).To(BeEmpty())
		})

		It("should forbid both secretRef and inline set", func() {
			errs := ValidateCABundle(&CABundle{
				SecretRef: &corev1.LocalObjectReference{Name: "my-secret"},
				Inline:    ptr.To(validCertPEM),
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
			errs := ValidateCABundle(&CABundle{Inline: ptr.To("")}, fldPath)
			Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("caBundle.inline"),
			}))))
		})

		It("should forbid non-PEM inline", func() {
			errs := ValidateCABundle(&CABundle{Inline: ptr.To("not-a-certificate")}, fldPath)
			Expect(errs).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("caBundle.inline"),
			}))))
		})

		It("should allow a valid inline PEM", func() {
			Expect(ValidateCABundle(&CABundle{Inline: ptr.To(validCertPEM)}, fldPath)).To(BeEmpty())
		})
	})
})
