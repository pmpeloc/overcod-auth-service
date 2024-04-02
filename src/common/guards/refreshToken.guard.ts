import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { JwtType } from '../constants/jwt';

@Injectable()
export class RefreshTokenGuard extends AuthGuard(JwtType.JWT_REFRESH_TOKEN) {}
