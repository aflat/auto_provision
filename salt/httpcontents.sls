renameindex:
  file.rename:
     - name:  /usr/share/nginx/html/index_orig.html
     - source:  /usr/share/nginx/html/index.html
     - force: True
createindeaxhtml:
  file.append:
     - name:  /usr/share/nginx/html/index.html
     - text: '<html><body>"Automation for the People"<sup>1</sup>
              </body>
              <style>
             p.padding{padding-top: 50%;font-size: 70%;}
             </style>
              <footer>
              <p class="padding">
              <sup>1</sup>
              This is probably a bit too literal, but I did not see the reference that the superscript 1 refered to in the directions, so I added one
              </p>
              </footer>
              </html>'