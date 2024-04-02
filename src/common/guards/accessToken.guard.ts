import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { JwtType } from '../constants/jwt';

@Injectable()
export class AccessTokenGuard extends AuthGuard(JwtType.JWT_ACCESS_TOKEN) {}
