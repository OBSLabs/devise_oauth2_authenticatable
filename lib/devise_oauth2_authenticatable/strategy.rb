require 'devise/strategies/base'
module Devise #:nodoc:
  module Oauth2Authenticatable #:nodoc:
    module Strategies #:nodoc:

      # Default strategy for signing in a user using Facebook Connect (a Facebook account).
      # Redirects to sign_in page if it's not authenticated
      #
      class Oauth2Authenticatable < ::Devise::Strategies::Base



        # Without a oauth session authentication cannot proceed.
        #
        def valid?

         valid_controller? && valid_params? && mapping.to.respond_to?('authenticate_with_oauth2')

        end

        # Authenticate user with OAuth2
        #
        def authenticate!
          klass = mapping.to
          client = Devise::oauth2_client
          begin

            # Verify User Auth code and get access token from auth server: will error on failue
            if verify_cookie_signature
              access_token = OAuth2::AccessToken.new(client, parse_cookie_information['access_token'])
            elsif params[:code]
              access_token = client.web_server.get_access_token(
                    params[:code], :redirect_uri => Devise::session_sign_in_url(request,mapping)
                  )
            end

            if access_token.nil?
              fail!('Facebook connect was canceled')
            else
              # retrieve user attributes

              # Get user details from OAuth2 Service
              # NOTE: Facebook Graph Specific
              # TODO: break this out into separate model or class to handle
              # different oauth2 providers
              oauth2_user_attributes = JSON.parse(access_token.get('/me'))

              user = klass.authenticate_with_oauth2(oauth2_user_attributes['id'], access_token.token)

              if !user.present?
                user = klass.authenticate_with_email(oauth2_user_attributes['email'], access_token.token)
              end

              if user.present?
                user.on_after_oauth2_connect(oauth2_user_attributes)
                success!(user)
              else
                if klass.oauth2_auto_create_account?
                  user = returning(klass.new) do |u|
                    u.store_oauth2_credentials!(
                        :token => access_token.token,
                        :uid => oauth2_user_attributes['id']
                      )
                    u.on_before_oauth2_auto_create(oauth2_user_attributes)
                  end
                  begin
                    user.save(true)
                    user.on_after_oauth2_connect(oauth2_user_attributes)
                    success!(user)
                  rescue
                    fail!(:oauth2_invalid)
                  end
                else
                  fail!(:oauth2_invalid)
                end
              end
            end
          rescue => e
            fail!(e.message)
            # raise e.message
          end
        end




        protected
          def valid_controller?
            # params[:controller] == 'sessions'
            mapping.controllers[:sessions] == params[:controller]
          end

          def valid_params?
            params[:code].present? || (params[:login_with_oauth2].present? &&  (params[:login_with_oauth2] == 'true'))
          end

          def parse_cookie_information
            app_id = Devise::OAUTH2_CONFIG['client_id']
            return nil if cookies["fbs_#{app_id}"].nil?
            Hash[*cookies["fbs_#{app_id}"].split('&').map { |v| v.gsub('"', '').split('=', 2) }.flatten]
          end


          def verify_cookie_signature
            secret = Devise::OAUTH2_CONFIG['client_secret']
            fb_keys = parse_cookie_information
            return false if fb_keys.nil?

            signature = fb_keys.delete('sig')
            return signature == Digest::MD5.hexdigest(fb_keys.map { |k, v| "#{k}=#{v}" }.sort.join + secret)
          end

      end
    end
  end
end

Warden::Strategies.add(:oauth2_authenticatable, Devise::Oauth2Authenticatable::Strategies::Oauth2Authenticatable)
