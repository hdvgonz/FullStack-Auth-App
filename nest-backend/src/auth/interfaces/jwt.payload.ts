/* eslint-disable prettier/prettier */
export interface JwtPayload {
  id: string;
  iat?: number;
  exp?: number;
}

//iat = fecha de cración
//exp = fecha de expiración.