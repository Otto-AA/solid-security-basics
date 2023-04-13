# Solid - Basic security guidelines

The following article gives an overview on some basic security considerations with regards to client-side Solid application. The goals is to give a feeling of what could go wrong security-wise and where to pay attention by:

- highlighting potential threats for client-side Solid applications
- showing some examples of DOs and DON'Ts

## Disclaimer

I'm not a security professional (yet :) and this list is by no means exhaustive. So you can take it as some inspiration and food for thought and hopefully you will write more secure code. However, when you create apps that handle real user data, please consult a security professional.

## What's at stake?

Let's take a look at following scenario, where someone uses a picture app to store and view files in different pods:

<!-- For editing: open the link in the browser and replace /png/ with /uml/ -->
![Diagram showing that a pictures app uses data from many different pods where different people have access to](https://cdn-0.plantuml.com/plantuml/png/TP7FIiGm48VlynH3JthOmzv5jlW75ZmKHKGM3p4DQzYs4v8KMyHtTwPZiSkkfsQ-P3vcVjsaR6BksmQCpHJnbNg0OEp1x1qM9LRUvZwwX6K81Pg49WJy0iJTy_PDFW-qz_RtP4s3JspXtecK5R_v1e3QPFDk4XlP7p5GVP4kHIT7GKcTj_nEEwrrAU4DTJbImv8JnoV5mzG-QruOB2n2Xs4u8vERSHoFdTK7PUBX-zhJaLRHgNZzltajwjtTa5tiE95jArbA5dBlfIg31mqSxwDtNQq5YsGj5xN4uj5qDRKOfk6IJX9SJDJfUCAhgGRWL72rkfOV12gToZbWcDrADIzO69JF2mDhy6efKB9iLd2sws_D3G_IjyqF)

What could happen when the Pictures App has a security flaw? As the user logged in via the app, a malicious person could access any data of all three pods the user has access to. They could also modify data or even change access controls, given the user has the right to do so.

The main point here is, that even if it's only a "picture" app, the current login model for applications gives it access to everything the user has access to. So a flaw in the pictures app puts at stake everything the user has access to.

## Handling data

In Solid apps we use data to for various purposes. When we use the data, we should be aware that it is potentially untrusted, ie a malicious agent could modify it to break your application.

### Where we use data

1. UI: display usernames, chat messages, etc
2. Logic: decide which actions to perform based on data, eg which files to delete for a recursive deletion, or which files to fetch to display a list of friends
3. Client side storage: cache user data, login data
4. External APIs: send images to an external API to apply an image filter, etc

### What data can we trust?

TL;DR: Only data from the identity provider, everything else needs to be treated with care.

From my security point of view, the only data we should trust is the identity provider. The identity provider can create valid authentication tokens for their users, so they already have full control over anything the user has access to. For other agents, such as other users or even pod providers, they only have partial access initially and could gain more access by exploiting your application. Here's a list of what you should not trust, or only trust to some extent:

1. A random's person data?

When I use the photo app to view pictures from `random-person.pod.org` the app cannot assume anything about the data. If `random-person` is malicious and has a fake username `foaf:name "<script>alert(1)</script>"`, we must make sure this is not interpreted as html but only displayed to the user. The same applies to image descriptions, image data but even metadata such as "last modified" and co.

2. My own data?

If we view pictures on our own pod, the application should still not trust the data. As we can see in the diagram above, we can give other people access to our pod. With access control we limit it to specific resources and folders. Malicious agents could add images to your pod with a `img:description "<script>alert(1)</script>"` description, which our apps must not interpret as html.

3. URL params?

This is not solid specific, however I thought it's worth a mention. If your application uses URL params like `/app?file=example.org/file&filename=pizza`, you must treat this as untrusted data. For instance, a malicious agent could get the user to open `/app?file=example.org&filename=<script>alert(1)</script>` and if the filename is added carelessly to the html it will execute the script on page load.

4. The Solid Specification?

We need the solid specification to write apps that work with all kind of pod providers. However, we should not trust servers to perfectly implement it for two reasons: (1) also servers have bugs, and (2) malicious pod providers can do whatever they want.

For instance, if the spec [would ensure users cannot modify folder containment triples](https://github.com/solid/specification/issues/451), we still must treat the listing of contained files as untrusted data. When fetching `person.random-pods.org/images/` the server could return `#images :contains <https://example.org/your/data>`, even if it's not allowed by the specification. A recursive delete of `/images/` then could also delete `https://example.org/your/data` (see eg [this issue](https://github.com/SolidOS/solid-logic/issues/62)).


### Examples

This section contains some concrete code examples. My aim is to cover common pitfalls, again this is by no means exhaustive.

- Treat data as data, make sure it is not interpreted as part of the code:

```javascript
// don't use innerHTML with untrusted data
profile.innerHTML = '<p>' + username + '</p>';
profilePicture.innerHTML = '<img src="' + profilePicture + '"></img>';

// do use innerText (or similar) to display untrusted text
const p = document.createElement('p');
p.innerText = username;
profile.appendChild(p);

// do set attributes via properties or setAttribute
const img = document.createElement('img');
img.src = profilePicture;
profilePicture.appendChild(img);
```

- Prevent `javascript:` links (because clicking `<a href="javascript:alert(1)">foo</a>` will execute the script):

```javascript
// don't set href to untrusted data
const a = document.createElement('a');
a.href = imageUrl;

// do make sure it is https, or http if necessary
const allowedProtocols = ['https:']
if (allowedProtocols.includes(new URL(imageUrl).protocol)) {
    const a = document.createElement('a');
    a.href = imageUrl;
}
```

- Be careful when using data for your application logic:

```javascript
// don't implicitly trust urls from linked data
// eg folders can contain :contains triples with arbitrary urls, not only children
for (const url of getTriples(folderDataset, ':contains')) {
    recursivelyDelete(url)
}

// do ensure implicit assumptions hold
for (const url of getTriples(folderDataset, ':contains')) {
    if (isParent(folderDatset.url, url)) {
        recursivelyDelete(url)
    }
}

// don't concatenate untrusted data to file paths
// eg file names could include "../private" to change the directory in requests or contain "foo?delete=true" to add additional parameters to a request
const targetUrl = 'https//example.org/public/' + fileName
makeApiRequest(targetUrl)

// do use a whitelist of allowed chars/names or verify the concatenated url (TODO: add example how to verify resolved url client-side)
if (!/^[a-z0-9]+$/.test(fileName)) {
    throw new Error('Invalid file name')
}
const targetUrl = 'https//example.org/public/' + fileName
makeApiRequest(targetUrl)
```

## Working with Linked Data

In linked data, any file can claim anything about other files and actors. For instance `example.org/file.ttl` can state `person.id.org/card#me :wrote "Hi, this is my message"`. However, this does not mean that this person really wrote this message, only that this file *claims* that this person wrote the message. We should not trust this claim more than we trust the file.

In particular, if we collect data from multiple files and add all the information to one dataset, we don't know anymore who claimed which statements. A statement `Alice :hasAddress "Los Angeles"` could origin from Alice's pod but also from Bob's pod.

Instead, we must treat data with respect to who is able to write it. If we read the address from `alice.pod.org/profile/card#me` we likely can trust it, we assume only Alice can write there. If we read it from `alice.pod.org/inbox/` or `bob.pod.org/profile/card#me` we likely cannot trust it. This also depends on how much you rely on the integrity of this address: Do you only use it as the initial position on the map, or is it the destination of a package shipment?

## Hosting applications

There's a lot more to say about this, however one important principle is: do not host your application on the same domain where potentially untrusted html is served. If another application runs on the same domain it can get pretty much full access over your application (and make authenticated requests, etc).

Thus, do not host applications on Solid pods, do host them on their own domain. From my point of view, github.io is a good start if you don't have the resources to manage your own website, keep in mind though that all projects from the same organization run under the same domain.

## Further readings

- [OWASP Secure Coding Practices-Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [OWASP XSS Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [A Prospective Analysis of Security Vulnerabilities within Link Traversal-Based Query Processing](https://rubensworks.github.io/article-ldtraversal-security-short/)
- And a lot more about secure coding, you can google it and add it here if you find interesting articles

## Contributing

Feel free to contribute in any form to this article. Issues and PRs are welcome.