# frozen_string_literal: true

# Remaps Chirpy layout names to Noir layouts when noir_theme is enabled.
# Controlled via `noir_theme` / `noir_stylesheet` in _config.yml. Chirpy files remain untouched.

module NoirTheme
  LAYOUT_MAP = {
    "compress" => "noir",
    "default" => "noir",
    "home" => "noir-home",
    "post" => "noir-post",
    "page" => "noir-page",
    "archives" => "noir-archives",
    "tags" => "noir-tags",
    "categories" => "noir-categories",
    "category" => "noir-list",
    "tag" => "noir-list",
    "archive-tags" => "noir-list",
    "archive-categories" => "noir-list"
  }.freeze

  def self.enabled?(site)
    site.config["noir_theme"] == true
  end

  def self.remap_layout!(doc)
    layout = doc.data["layout"]
    return if layout.nil? || layout.to_s.empty?

    mapped = LAYOUT_MAP[layout]
    doc.data["layout"] = mapped if mapped
  end

  def self.remap_site!(site)
    return unless enabled?(site)

    site.pages.each { |page| remap_layout!(page) }
    site.posts.docs.each { |post| remap_layout!(post) }
    site.documents.each { |doc| remap_layout!(doc) }
  end
end

# Early remap for pages read from disk (tabs, etc.)
Jekyll::Hooks.register :site, :post_read do |site|
  NoirTheme.remap_site!(site)
end

# jekyll-archives appends tag/category pages in a Generator *after* :post_read.
# Remap again when all generators have finished.
class NoirThemeRemapGenerator < Jekyll::Generator
  safe true
  priority :lowest

  def generate(site)
    NoirTheme.remap_site!(site)
  end
end
