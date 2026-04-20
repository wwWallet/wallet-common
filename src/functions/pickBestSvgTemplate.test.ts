import { describe, expect, it } from "vitest";
import type { SvgTemplateEntry } from "../schemas/SdJwtVcTypeMetadataSchema";
import { pickBestSvgTemplate } from "./pickBestSvgTemplate";

describe("pickBestSvgTemplate", () => {
	const realisticTemplates: SvgTemplateEntry[] = [
		{
			uri: "https://example.com/portrait-light-normal.svg",
			properties: {
				orientation: "portrait",
				color_scheme: "light",
				contrast: "normal",
			},
		},
		{
			uri: "https://example.com/portrait-dark-normal.svg",
			properties: {
				orientation: "portrait",
				color_scheme: "dark",
				contrast: "normal",
			},
		},
		{
			uri: "https://example.com/portrait-dark-high.svg",
			properties: {
				orientation: "portrait",
				color_scheme: "dark",
				contrast: "high",
			},
		},
		{
			uri: "https://example.com/landscape-light-normal.svg",
			properties: {
				orientation: "landscape",
				color_scheme: "light",
				contrast: "normal",
			},
		},
		{
			uri: "https://example.com/landscape-dark-high.svg",
			properties: {
				orientation: "landscape",
				color_scheme: "dark",
				contrast: "high",
			},
		},
	];

	it("returns null when there are no templates", () => {
		expect(
			pickBestSvgTemplate(undefined, { orientation: "portrait" })
		).toBeNull();
		expect(
			pickBestSvgTemplate([], { orientation: "portrait" })
		).toBeNull();
	});

	it("returns the only template when one exists", () => {
		const template: SvgTemplateEntry = { uri: "https://example.com/only.svg" };

		expect(
			pickBestSvgTemplate([template], { orientation: "portrait" })
		).toEqual(template);
	});

	it("prefers the template that matches orientation", () => {
		const templates: SvgTemplateEntry[] = [
			{
				uri: "https://example.com/landscape.svg",
				properties: { orientation: "landscape" },
			},
			{
				uri: "https://example.com/portrait.svg",
				properties: { orientation: "portrait" },
			},
		];

		expect(
			pickBestSvgTemplate(templates, { orientation: "portrait" })
		).toEqual(templates[1]);
	});

	it("narrows matches with color scheme and contrast", () => {
		expect(
			pickBestSvgTemplate(realisticTemplates, {
				orientation: "portrait",
				color_scheme: "dark",
				contrast: "high",
			})
		).toEqual(realisticTemplates[2]);
	});

	it("falls back to all templates when no orientation match exists", () => {
		const templates: SvgTemplateEntry[] = [
			{
				uri: "https://example.com/light.svg",
				properties: { orientation: "landscape", color_scheme: "light" },
			},
			{
				uri: "https://example.com/dark.svg",
				properties: { orientation: "landscape", color_scheme: "dark" },
			},
		];

		expect(
			pickBestSvgTemplate(templates, {
				orientation: "portrait",
				color_scheme: "dark",
			})
		).toEqual(templates[1]);
	});

	it("prefers a candidate with properties when fallback candidates remain", () => {
		const templates: SvgTemplateEntry[] = [
			{ uri: "https://example.com/without-properties.svg" },
			{
				uri: "https://example.com/with-properties.svg",
				properties: { orientation: "portrait" },
			},
		];

		expect(
			pickBestSvgTemplate(templates, { color_scheme: "light" })
		).toEqual(templates[1]);
	});

	it("keeps orientation matches even when color scheme does not match", () => {
		const templates: SvgTemplateEntry[] = [
			{
				uri: "https://example.com/portrait-dark.svg",
				properties: {
					orientation: "portrait",
					color_scheme: "dark",
				},
			},
			{
				uri: "https://example.com/portrait-dark-high.svg",
				properties: {
					orientation: "portrait",
					color_scheme: "dark",
					contrast: "high",
				},
			},
			{
				uri: "https://example.com/landscape-light.svg",
				properties: {
					orientation: "landscape",
					color_scheme: "light",
				},
			},
		];

		expect(
			pickBestSvgTemplate(templates, {
				orientation: "portrait",
				color_scheme: "light",
			})
		).toEqual(templates[0]);
	});

	it("uses contrast to break a tie among templates with the same orientation", () => {
		expect(
			pickBestSvgTemplate(realisticTemplates, {
				orientation: "landscape",
				contrast: "high",
			})
		).toEqual(realisticTemplates[4]);
	});

	it("supports templates with partial properties alongside fully specified ones", () => {
		const templates: SvgTemplateEntry[] = [
			{
				uri: "https://example.com/portrait-only.svg",
				properties: { orientation: "portrait" },
			},
			{
				uri: "https://example.com/portrait-dark.svg",
				properties: {
					orientation: "portrait",
					color_scheme: "dark",
				},
			},
			{
				uri: "https://example.com/portrait-dark-high.svg",
				properties: {
					orientation: "portrait",
					color_scheme: "dark",
					contrast: "high",
				},
			},
		];

		expect(
			pickBestSvgTemplate(templates, {
				orientation: "portrait",
				color_scheme: "dark",
				contrast: "high",
			})
		).toEqual(templates[2]);
	});

	it("returns the first matching template when multiple templates share the same properties", () => {
		const templates: SvgTemplateEntry[] = [
			{
				uri: "https://example.com/first-portrait-dark.svg",
				properties: {
					orientation: "portrait",
					color_scheme: "dark",
				},
			},
			{
				uri: "https://example.com/second-portrait-dark.svg",
				properties: {
					orientation: "portrait",
					color_scheme: "dark",
				},
			},
		];

		expect(
			pickBestSvgTemplate(templates, {
				orientation: "portrait",
				color_scheme: "dark",
			})
		).toEqual(templates[0]);
	});
});
