# define VAR_FragColor "vi"
# define VAR_FragPos "et"
# define VAR_Normal "cu"
# define VAR_lightColor "ok"
# define VAR_lightPos "me"
# define VAR_objectColor "it"

#version 330 core
out vec4 vi;
in vec3 cu,et;
uniform vec3 me,ok,it;
void main()
{
  vec3 d=.1*ok,n=normalize(cu),r=normalize(me-e);
  float a=max(dot(n,r),0.);
  vec3 t=a*ok,l=(d+t)*it;
  vi=vec4(l,1.);
}

