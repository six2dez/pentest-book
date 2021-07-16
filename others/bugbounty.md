# BugBounty

## Good PoC

<table>
  <thead>
    <tr>
      <th style="text-align:left">Issue type</th>
      <th style="text-align:left">PoC</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Cross-site scripting</td>
      <td style="text-align:left"><a href="javascript:alert(document.domain)"><code>alert(document.domain)</code></a> or <code>setInterval`alert\x28document.domain\x29`</code> if
        you have to use backticks. <a href="https://medium.com/@know.0nix/jumping-to-the-hell-with-10-attempts-to-bypass-devils-waf-4275bfe679dd">[1]</a> Using <code>document.domain</code> instead
        of <code>alert(1)</code> can help avoid reporting XSS bugs in sandbox domains.</td>
    </tr>
    <tr>
      <td style="text-align:left">Command execution</td>
      <td style="text-align:left">
        <p>Depends of program rules:</p>
        <ul>
          <li>Read (Linux-based): <code>cat /proc/1/maps</code>
          </li>
          <li>Write (Linux-based): <code>touch /root/your_username</code>
          </li>
          <li>Execute (Linux-based): <code>id</code>
          </li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Code execution</td>
      <td style="text-align:left">
        <p>This involves the manipulation of a web app such that server-side code
          (e.g. PHP) is executed.</p>
        <ul>
          <li>PHP: <code>&lt;?php echo 7*7; ?&gt;</code>
          </li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">SQL injection</td>
      <td style="text-align:left">
        <p>Zero impact</p>
        <ul>
          <li>MySQL and MSSQL: <code>SELECT @@version</code>
          </li>
          <li>Oracle: <code>SELECT version FROM v$instance;</code>
          </li>
          <li>Postgres SQL: <code>SELECT version()</code>
          </li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Unvalidated redirect</td>
      <td style="text-align:left">
        <ul>
          <li>Set the redirect endpoint to a known safe domain (e.g. <code>google.com</code>),
            or if looking to demonstrate potential impact, to your own website with
            an example login screen resembling the target&apos;s.</li>
          <li>If the target uses OAuth, you can try to leak the OAuth token to your
            server to maximise impact.</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Information exposure</td>
      <td style="text-align:left">Investigate only with the IDs of your own test accounts &#x2014; do not
        leverage the issue against other users&apos; data &#x2014; and describe
        your full reproduction process in the report.</td>
    </tr>
    <tr>
      <td style="text-align:left">Cross-site request forgery</td>
      <td style="text-align:left">When designing a real-world example, either hide the form (<code>style=&quot;display:none;&quot;</code>)
        and make it submit automatically, or design it so that it resembles a component
        from the target&apos;s page.</td>
    </tr>
    <tr>
      <td style="text-align:left">Server-side request forgery</td>
      <td style="text-align:left">
        <p>The impact of a SSRF bug will vary &#x2014; a non-exhaustive list of proof
          of concepts includes:</p>
        <ul>
          <li>reading local files</li>
          <li>obtaining cloud instance metadata</li>
          <li>making requests to internal services (e.g. Redis)</li>
          <li>accessing firewalled databases</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Local file read</td>
      <td style="text-align:left">Make sure to only retrieve a harmless file. Check the program security
        policy as a specific file may be designated for testing.</td>
    </tr>
    <tr>
      <td style="text-align:left">XML external entity processing</td>
      <td style="text-align:left">Output random harmless data.</td>
    </tr>
    <tr>
      <td style="text-align:left">Sub-domain takeover</td>
      <td style="text-align:left">Claim the sub-domain discreetly and serve a harmless file on a hidden
        page. Do not serve content on the index page.</td>
    </tr>
  </tbody>
</table>

## Good Report

```text
# Writeups
# https://github.com/devanshbatham/Awesome-Bugbounty-Writeups
```

```text
# Bug bounty Report

# Summary
...

# Vulnerability details
...

# Impact
...

# Proof of concept
...

# Browsers verified in
...

# Mitigation
...
```

