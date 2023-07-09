# define VAR_FragPos "nl"
# define VAR_Normal "gp"
# define VAR_aNormal "ir"
# define VAR_aPos "vh"
# define VAR_model "lp"
# define VAR_projection "ch"
# define VAR_view "or"

#version 330 core
layout(location=0) in vec3 vh;
layout(location=1) in vec3 ir;
out vec3 nl,gp;
uniform mat4 lp,or,ch;
void main()
{
  nl=vec3(lp*vec4(vh,1.));
  gp=ir;
  gl_Position=ch*or*vec4(nl,1.);
}

