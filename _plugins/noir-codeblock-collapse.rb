# frozen_string_literal: true

# Collapsed-by-default code blocks for noir-code-collapse.js
#
# Required HTML (Rouge/Kramdown) before the JS runs:
#   <div class="language-c collapsed highlighter-rouge">
#     <motion class="highlight"><pre class="highlight"><code>...</code></pre></div>
#   </div>
#
# The +collapsed+ class on +.highlighter-rouge+ makes the block start with
# +.code-block-wrap.is-collapsed+ after enhancement.
#
# Markdown (all normalized to a trailing IAL before render):
#   ```c collapse
#   ```c {.collapsed}
#   ```c
#   ...
#   ```
#   {: .collapsed}

module NoirCodeblockCollapse
  FENCE_OPEN_RE = /
    ^(`{3,})       # opening backticks
    ([^\n`]+)      # info string
    \s*$
  /mx.freeze

  COLLAPSE_TOKEN = /\b(?:collapse|collapsed)\b/i.freeze
  IAL_COLLAPSE_RE = /\{\s*\.?(?:collapse|collapsed)\s*\}/i.freeze

  def self.collapse_requested?(info)
    info.match?(COLLAPSE_TOKEN) || info.match?(IAL_COLLAPSE_RE)
  end

  def self.strip_language(info)
    lang = info.gsub(IAL_COLLAPSE_RE, "").gsub(COLLAPSE_TOKEN, "").strip
    lang.empty? ? "plaintext" : lang
  end

  def self.process_markdown!(content)
    return if content.nil? || content.empty?

    lines = content.lines
    i = 0
    out = []

    while i < lines.length
      line = lines[i]
      match = FENCE_OPEN_RE.match(line)

      unless match
        out << line
        i += 1
        next
      end

      ticks = match[1]
      info = match[2].strip
      collapse = collapse_requested?(info)

      if collapse
        out << "#{ticks}#{strip_language(info)}\n"
      else
        out << line
      end
      i += 1

      next unless collapse

      close_ticks = ticks
      while i < lines.length
        out << lines[i]
        if lines[i].strip == close_ticks
          out << "{: .collapsed}\n" unless lines[i + 1]&.match?(/^\s*\{:\s*\.collapsed\s*\}/)
          i += 1
          break
        end
        i += 1
      end
    end

    content.replace(out.join)
  end
end

%i(posts pages).each do |collection|
  Jekyll::Hooks.register collection, :pre_render do |doc|
    next unless doc.respond_to?(:content) && doc.content.is_a?(String)
    next unless doc.extname&.match?(/\.md|\.markdown/i)

    NoirCodeblockCollapse.process_markdown!(doc.content)
  end
end
